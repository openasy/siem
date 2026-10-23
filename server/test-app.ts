// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createSiem, type SiemOptions } from "./siem.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

/** A rule in Sigma YAML. */
export const rule = (title: string, detection: string, level = "high") => `title: ${title}\nlevel: ${level}\ndetection:\n${detection.replace(/^/gm, "  ")}\n`;

export const FAILED_LOGIN = rule("Failed login", "selection:\n  message|contains: 'Failed password'\ncondition: selection", "medium");
export const MIMIKATZ = rule(
  "Credential dumping tool",
  "selection:\n  Image|endswith: '\\\\mimikatz.exe'\nfilter:\n  User: SYSTEM\ncondition: selection and not filter",
  "critical",
);

export async function startApp(opts: Omit<Partial<AppOptions>, "siem"> & { version: string; siem?: SiemOptions }) {
  const db = openDb(":memory:");
  const siem = createSiem(db, opts.siem);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "siem", productName: "OpenAsy SIEM", origin: base });
  const { siem: _options, ...rest } = opts;
  handler = createApp({ db, siem, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...rest });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends events the way a shipper does. */
  const send = (events: unknown) => ingest("/api/v1/events", { method: "POST", body: JSON.stringify(events) });
  const addRule = (source: string, enabled = true) => admin("/api/v1/rules", { method: "POST", body: JSON.stringify({ source, enabled }) });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, siem, auth, base, admin, ingest, send, addRule, close };
}
