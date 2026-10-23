import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, FAILED_LOGIN, INGEST_TOKEN, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "siem-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // siem's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let rule = "";
  let signal = "";
  let event = 0;
  const at = new Date(Date.now() - 60_000).toISOString();
  const ssh = { time: at, host: "web-1", source: "sshd", message: "Failed password for root", port: 22, ok: false, extra: null };
  const events = (body: unknown) => auth(INGEST_TOKEN, JSON.stringify(body));

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("rules: add, test, change, and every refusal", async () => {
    rule = ((await call("POST", "/api/v1/rules", admin({ source: FAILED_LOGIN }))).body as { id: string }).id;
    await call("POST", "/api/v1/rules", admin({ source: "title: Broken" }));
    await call("POST", "/api/v1/rules", admin({ source: FAILED_LOGIN, extra: 1 }));
    await call("POST", "/api/v1/rules", admin("nope"));
    await call("POST", "/api/v1/rules", admin({ source: "x".repeat(70_000) }));
    await call("POST", "/api/v1/rules", {});
    await call("GET", "/api/v1/rules", admin());
    await call("GET", "/api/v1/rules", admin(), "/api/v1/rules?limit=1");
    await call("GET", "/api/v1/rules", admin(), "/api/v1/rules?limit=0");
    await call("GET", "/api/v1/rules", {});
    await call("GET", "/api/v1/rules/{id}", admin(), `/api/v1/rules/${rule}`);
    await call("GET", "/api/v1/rules/{id}", admin(), "/api/v1/rules/missing");
    await call("POST", "/api/v1/rules/test", admin({ source: FAILED_LOGIN }));
    await call("POST", "/api/v1/rules/test", admin({ source: "title: Broken" }));
    await call("POST", "/api/v1/rules/test", admin({ source: FAILED_LOGIN, limit: 0 }));
    await call("POST", "/api/v1/rules/test", {});
    await call("PATCH", "/api/v1/rules/{id}", admin({ enabled: false }), `/api/v1/rules/${rule}`);
    await call("PATCH", "/api/v1/rules/{id}", admin({ enabled: true, source: FAILED_LOGIN }), `/api/v1/rules/${rule}`);
    await call("PATCH", "/api/v1/rules/{id}", admin({}), `/api/v1/rules/${rule}`);
    await call("PATCH", "/api/v1/rules/{id}", admin({ enabled: false }), "/api/v1/rules/missing");
    await call("PATCH", "/api/v1/rules/{id}", { method: "PATCH" }, `/api/v1/rules/${rule}`);
  });

  it("events: send, search, read", async () => {
    await call("POST", "/api/v1/events", events(ssh));
    await call("POST", "/api/v1/events", events([ssh, { ...ssh, host: "web-2" }]));
    await call("POST", "/api/v1/events", events([{ nested: { a: 1 } }]));
    await call("POST", "/api/v1/events", events([]));
    await call("POST", "/api/v1/events", events(Array.from({ length: 1001 }, () => ({}))));
    await call("POST", "/api/v1/events", auth(INGEST_TOKEN, "{nope"));
    await call("POST", "/api/v1/events", auth("wrong", "{}"));
    await call("POST", "/api/v1/events", { method: "POST" });
    const list = (await call("GET", "/api/v1/events", admin())).body as { events: Array<{ id: number }> };
    event = list.events[0]!.id;
    await call("GET", "/api/v1/events", admin(), "/api/v1/events?host=web-1&source=sshd&q=password&since=2020-01-01&until=2100-01-01&limit=1");
    await call("GET", "/api/v1/events", admin(), "/api/v1/events?since=yesterday");
    await call("GET", "/api/v1/events", {});
    await call("GET", "/api/v1/events/{id}", admin(), `/api/v1/events/${event}`);
    await call("GET", "/api/v1/events/{id}", admin(), "/api/v1/events/999999");
    await call("GET", "/api/v1/events/{id}", {}, `/api/v1/events/${event}`);
  });

  it("signals", async () => {
    const { body } = await call("GET", "/api/v1/signals", admin());
    const signals = (body as { signals: Array<{ id: string; count: number }> }).signals;
    expect(signals).toHaveLength(2);
    signal = signals[0]!.id;
    await call("GET", "/api/v1/signals", admin(), "/api/v1/signals?status=closed&severity=medium,high&host=web-1&rule=" + rule + "&limit=1");
    await call("GET", "/api/v1/signals", admin(), "/api/v1/signals?severity=urgent");
    await call("GET", "/api/v1/signals", {});
    await call("GET", "/api/v1/signals/{id}", admin(), `/api/v1/signals/${signal}`);
    await call("GET", "/api/v1/signals/{id}", admin(), "/api/v1/signals/missing");
    await call("PATCH", "/api/v1/signals/{id}", admin({ status: "investigating" }), `/api/v1/signals/${signal}`);
    await call("PATCH", "/api/v1/signals/{id}", admin({ status: "false-positive" }), `/api/v1/signals/${signal}`);
    await call("PATCH", "/api/v1/signals/{id}", admin({ status: "false-positive", reason: "A scanner we run" }), `/api/v1/signals/${signal}`);
    await call("PATCH", "/api/v1/signals/{id}", admin("nope"), `/api/v1/signals/${signal}`);
    await call("PATCH", "/api/v1/signals/{id}", admin({ status: "closed" }), "/api/v1/signals/missing");
    await call("PATCH", "/api/v1/signals/{id}", { method: "PATCH" }, `/api/v1/signals/${signal}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("deletes a rule", async () => {
    await call("DELETE", "/api/v1/rules/{id}", admin(), `/api/v1/rules/${rule}`);
    await call("DELETE", "/api/v1/rules/{id}", admin(), `/api/v1/rules/${rule}`);
    await call("DELETE", "/api/v1/rules/{id}", { method: "DELETE" }, "/api/v1/rules/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
