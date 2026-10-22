import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";
import type { Level } from "./sigma.ts";
import { LEVELS, parseLimit, SiemError, type ProblemCode, type Siem, type Status } from "./siem.ts";

export interface AppOptions {
  db: DatabaseSync;
  siem: Siem;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** Token log shippers send events with. It can add events and nothing else (ADR 0003). An API token with the editor role works too. */
  ingestToken?: string;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(siem: Siem, version: string) {
  const s = siem.summary();
  return renderMetrics(version, { events: s.events, eventsLastDay: s.eventsLastDay, rules: s.rules, signals: s.open });
}

/** Serves only /metrics, for a port that is not exposed with the rest (SIEM_METRICS_PORT). */
export function createMetricsHandler(siem: Siem, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(siem, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
};

/** Largest body of events accepted, after decompression. */
const EVENTS_LIMIT = 16 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) => send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "invalid-event": "Invalid event",
  "invalid-rule": "Invalid rule",
  "not-found": "Not found",
  conflict: "Conflict",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new SiemError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new SiemError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof SiemError) throw err;
    throw new SiemError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 256 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof SiemError && err.code === "payload-too-large") throw new SiemError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new SiemError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), or "ingest" for scans sent from CI. */
type Access = "none" | "ingest" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the audit trail of a decision. */
  actor: () => string;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

function oneOf<T extends string>(url: URL, name: string, allowed: readonly T[]): T | undefined {
  const v = url.searchParams.get(name);
  if (v === null) return undefined;
  if (!allowed.includes(v as T)) throw new SiemError(422, "invalid-body", `${name} must be one of ${allowed.join(", ")}.`);
  return v as T;
}

function time(url: URL, name: string): string | undefined {
  const v = url.searchParams.get(name);
  if (v === null) return undefined;
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw new SiemError(422, "invalid-body", `${name} must be an ISO 8601 date.`);
  return new Date(t).toISOString();
}

const text = (url: URL, name: string, max = 128) => {
  const v = url.searchParams.get(name)?.trim();
  if (v && v.length > max) throw new SiemError(422, "invalid-body", `${name} must be at most ${max} characters.`);
  return v || undefined;
};

export function createApp({ db, siem, version, auth, adminToken, ingestToken, webDir, docsDir, openapi, serveMetrics = true, products = [] }: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));
  const page = <K extends string, T>(key: K, p: { items: T[]; nextCursor?: string }) => ({ [key]: p.items, ...(p.nextCursor && { nextCursor: p.nextCursor }) }) as Record<K, T[]> & { nextCursor?: string };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "siem", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => siem.summary() },

    // Events in, from log shippers, agents and scripts. A single event or an array.
    {
      method: "POST",
      path: "/api/v1/events",
      auth: "ingest",
      handle: async ({ req, res }) => {
        let body: unknown;
        try {
          body = JSON.parse((await readBody(req, EVENTS_LIMIT)).toString("utf8"));
        } catch (err) {
          if (err instanceof SiemError) throw err;
          throw new SiemError(400, "invalid-json", "The body must be a JSON event or an array of events.");
        }
        json(res, 202, siem.ingest(body));
      },
    },
    {
      method: "GET",
      path: "/api/v1/events",
      auth: "viewer",
      handle: ({ url }) => page("events", siem.searchEvents({ host: text(url, "host"), source: text(url, "source"), q: text(url, "q"), since: time(url, "since"), until: time(url, "until") }, cursor(url), limit(url))),
    },
    {
      method: "GET",
      path: "/api/v1/events/:id",
      auth: "viewer",
      handle: ({ params }) => {
        if (!/^\d{1,15}$/.test(params[0]!)) throw new SiemError(404, "not-found", "The event does not exist.");
        return siem.event(Number(params[0]));
      },
    },

    // Rules.
    { method: "GET", path: "/api/v1/rules", auth: "viewer", handle: ({ url }) => page("rules", siem.listRules(cursor(url), limit(url))) },
    { method: "POST", path: "/api/v1/rules", auth: "admin", handle: async ({ res, body, actor }) => json(res, 201, siem.createRule(await body(), actor())) },
    // Before /rules/:id so "test" is not taken for an id.
    { method: "POST", path: "/api/v1/rules/test", auth: "editor", handle: async ({ body }) => siem.testRule(await body()) },
    { method: "GET", path: "/api/v1/rules/:id", auth: "viewer", handle: ({ params }) => siem.rule(params[0]!) },
    { method: "PATCH", path: "/api/v1/rules/:id", auth: "admin", handle: async ({ params, body }) => siem.updateRule(params[0]!, await body()) },
    { method: "DELETE", path: "/api/v1/rules/:id", auth: "admin", handle: ({ res, params }) => (siem.deleteRule(params[0]!), noContent(res)) },

    // Signals.
    {
      method: "GET",
      path: "/api/v1/signals",
      auth: "viewer",
      handle: ({ url }) => {
        const severity = url.searchParams.get("severity")?.split(",").filter(Boolean) as Level[] | undefined;
        if (severity?.some((s) => !LEVELS.includes(s))) throw new SiemError(422, "invalid-body", `severity is a comma-separated list of ${LEVELS.join(", ")}.`);
        const status = oneOf(url, "status", ["open", "new", "investigating", "closed", "false-positive"] as const) as Status | "open" | undefined;
        return page("signals", siem.signals({ status: status ?? "open", severity, host: text(url, "host"), rule: text(url, "rule") }, cursor(url), limit(url)));
      },
    },
    { method: "GET", path: "/api/v1/signals/:id", auth: "viewer", handle: ({ params }) => siem.signal(params[0]!) },
    { method: "PATCH", path: "/api/v1/signals/:id", auth: "editor", handle: async ({ params, body, actor }) => siem.setStatus(params[0]!, await body(), actor()) },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for the ingest token. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none") return null;
    if (access === "ingest" && tokenMatches(req.headers.authorization, ingestToken)) return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    if (access === "ingest") {
      // An API token or a session with the editor role can send scans too, for CI set up from Settings.
      if (!ingestToken && !req.headers.authorization?.startsWith("Bearer oa_")) throw new SiemError(503, "not-configured", "Set SIEM_INGEST_TOKEN on siem, or send an API token with the editor role.");
      if (!req.headers.authorization?.startsWith("Bearer oa_")) throw new SiemError(401, "invalid-token", "Send SIEM_INGEST_TOKEN or an API token as a bearer token.");
    }
    const p = auth.authorize(req, access === "ingest" ? "editor" : access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take scans as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(siem, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), actor: () => who ?? "unknown" });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof SiemError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string, which may name hosts and images. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
