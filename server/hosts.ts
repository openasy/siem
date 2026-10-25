// The install's servers from a file, the same file for every product that works with servers (ADR 0052). Each product
// reads what it needs: Infrastructure and Logs reach every entry over SSH; Vulnerabilities, Posture, Malware and
// Backups show which servers they have nothing for. This file is the same in each of those products; keep the copies
// in step (server/testdata/hosts.yaml is shared too).
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { parse } from "yaml";

export interface HostEntry {
  /** Unique in the file, and how the entry is found again when the file changes. Endpoints name it as `server`. */
  name: string;
  address: string;
  port: number;
  user: string;
  auth: "certificate" | "key";
  /** With auth key: a private key in the agent's key folder, read by the agent alone; the agent's own key without it. */
  keyFile: string | null;
  containers: boolean;
  /** Another entry's name: the host this one is reached through. */
  jump: string | null;
  /** The name of the product's agent that reaches it; each product has its own agents, named alike. */
  agent: string | null;
  /**
   * SHA256:... as ssh-keygen -lf prints it: the key is trusted when the host presents it. first: the key the host
   * presents the first time is trusted, and a different one later waits for an admin. Unset: an admin accepts it.
   */
  hostKey: string | null;
  tags: Record<string, string>;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
// Never starts with "-": a value that ssh could read as an option.
const ADDRESS = /^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$|^\[[0-9a-fA-F:]+\]$/;
const USER = /^[a-z_][a-z0-9_-]{0,31}$/;
const FINGERPRINT = /^SHA256:[A-Za-z0-9+/]{43}$/;
const TAG = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,62}$/;
// A file name, never a path: no slash, so the agent never reads outside its key folder, and no leading dot.
const KEY_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const KEYS = ["name", "address", "port", "user", "auth", "keyFile", "containers", "jump", "agent", "hostKey", "tags"];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Reads the file's text. Throws with the entry and field at fault, so one message says what to fix. */
export function parseHosts(text: string): HostEntry[] {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    throw new Error(`Not valid YAML: ${(err as Error).message.split("\n")[0]}`);
  }
  if (doc === null || doc === undefined) return [];
  if (!isObj(doc) || Object.keys(doc).some((k) => k !== "hosts")) throw new Error("The file holds one list, hosts:, and nothing else.");
  const list = doc.hosts ?? [];
  if (!Array.isArray(list)) throw new Error("hosts must be a list.");
  if (list.length > 5000) throw new Error("hosts holds at most 5000 entries.");
  const seen = new Set<string>();
  const hosts = list.map((h, i): HostEntry => {
    const at = `hosts[${i}]`;
    if (!isObj(h)) throw new Error(`${at} must be a map with at least name and address.`);
    const extra = Object.keys(h).filter((k) => !KEYS.includes(k));
    if (extra.length) throw new Error(`${at}: unknown ${extra.join(", ")}; an entry takes ${KEYS.join(", ")}.`);
    if (typeof h.name !== "string" || !NAME.test(h.name)) throw new Error(`${at}.name is required: letters, digits, dots, dashes and underscores, up to 63.`);
    if (seen.has(h.name.toLowerCase())) throw new Error(`${at}.name: ${h.name} is in the file twice.`);
    seen.add(h.name.toLowerCase());
    const where = `${at} (${h.name})`;
    if (typeof h.address !== "string" || !ADDRESS.test(h.address)) throw new Error(`${where}.address is required: a host name or IP address.`);
    if (h.port !== undefined && (!Number.isInteger(h.port) || (h.port as number) < 1 || (h.port as number) > 65535))
      throw new Error(`${where}.port is 1 to 65535.`);
    if (h.user !== undefined && (typeof h.user !== "string" || !USER.test(h.user))) throw new Error(`${where}.user is a Unix account name.`);
    if (h.auth !== undefined && h.auth !== "certificate" && h.auth !== "key") throw new Error(`${where}.auth is certificate or key.`);
    if (h.keyFile !== undefined && h.keyFile !== null) {
      if (typeof h.keyFile !== "string" || !KEY_FILE.test(h.keyFile))
        throw new Error(`${where}.keyFile is a file name in the agent's key folder, such as web-1.key: no folders, up to 128.`);
      if (h.auth !== "key") throw new Error(`${where}.keyFile needs auth: key.`);
    }
    if (h.containers !== undefined && typeof h.containers !== "boolean") throw new Error(`${where}.containers is true or false.`);
    for (const k of ["jump", "agent"] as const) {
      if (h[k] !== undefined && h[k] !== null && (typeof h[k] !== "string" || !NAME.test(h[k] as string)))
        throw new Error(`${where}.${k} is a name: letters, digits, dots, dashes and underscores, up to 63.`);
    }
    if (h.hostKey !== undefined && h.hostKey !== null && h.hostKey !== "first" && (typeof h.hostKey !== "string" || !FINGERPRINT.test(h.hostKey))) {
      throw new Error(`${where}.hostKey is a fingerprint as ssh-keygen -lf prints it, such as SHA256:${"A".repeat(43)}, or first to trust the first key.`);
    }
    if (
      h.tags !== undefined &&
      (!isObj(h.tags) || Object.keys(h.tags).length > 32 || Object.entries(h.tags).some(([k, v]) => !TAG.test(k) || typeof v !== "string" || v.length > 128))
    ) {
      throw new Error(`${where}.tags is a map of up to 32 name: value texts, such as { env: prod }.`);
    }
    return {
      name: h.name,
      address: h.address,
      port: (h.port as number | undefined) ?? 22,
      user: (h.user as string | undefined) ?? "openasy",
      auth: (h.auth as HostEntry["auth"] | undefined) ?? "certificate",
      keyFile: (h.keyFile as string | null | undefined) ?? null,
      containers: h.containers === true,
      jump: (h.jump as string | null | undefined) ?? null,
      agent: (h.agent as string | null | undefined) ?? null,
      hostKey: (h.hostKey as string | null | undefined) ?? null,
      tags: (h.tags as Record<string, string> | undefined) ?? {},
    };
  });
  const byName = new Map(hosts.map((h) => [h.name, h]));
  for (const h of hosts) {
    if (!h.jump) continue;
    const j = byName.get(h.jump);
    if (!j) throw new Error(`${h.name}.jump: ${h.jump} is not a host in the file.`);
    if (j.name === h.name) throw new Error(`${h.name}.jump: a host cannot be its own jump host.`);
    if (j.jump) throw new Error(`${h.name}.jump: ${j.name} is reached through ${j.jump} itself; a jump host must be reachable directly.`);
  }
  return hosts;
}

/**
 * The servers in the file a product has nothing for (ADR 0052). Products that are sent what they know about servers,
 * such as scans, reports or backups, show which servers are missing. A server counts as seen when a product knows it
 * by its name or address, ignoring case; a full name such as web-1.example.com also counts for web-1.
 */
export function missingHosts(hosts: HostEntry[], seen: Iterable<string>): HostEntry[] {
  const known = new Set<string>();
  for (const x of seen) {
    const v = x.trim().toLowerCase();
    if (!v) continue;
    known.add(v);
    if (/[a-z]/.test(v) && v.includes(".")) known.add(v.slice(0, v.indexOf(".")));
  }
  return hosts.filter((h) => !known.has(h.name.toLowerCase()) && !known.has(h.address.toLowerCase()));
}

export interface HostsFileState {
  path: string;
  /** When the file was last read and applied, or null if it never was. */
  appliedAt: string | null;
  entries: number;
  /** Why the file on disk is not what is applied; the last good list stays until it is fixed. */
  error: string | null;
  /** Things to fix that did not stop the file from being applied. */
  warnings: string[];
}

/**
 * Reads the file now and whenever it changes (checked every `everyMs`, by size, time and content), and hands each new
 * list to `apply`, which returns warnings or throws to refuse it. While the last apply had warnings, such as a host
 * whose agent is not enrolled yet, the same list is applied again at every check, so it is picked up once it can be.
 * A file that cannot be read or applied leaves the last good list in place. `stop()` ends the polling.
 */
export function watchHosts(
  path: string,
  apply: (hosts: HostEntry[]) => string[],
  { everyMs = 60_000, onChange }: { everyMs?: number; onChange?: (state: HostsFileState) => void } = {},
) {
  const state: HostsFileState = { path, appliedAt: null, entries: 0, error: null, warnings: [] };
  let seen = "";
  const read = () => {
    let text: string;
    let stamp: string;
    try {
      const st = statSync(path);
      text = readFileSync(path, "utf8");
      stamp = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(text).digest("hex")}`;
    } catch (err) {
      const error = `Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;
      if (state.error !== error) ((state.error = error), onChange?.(state));
      return;
    }
    if (stamp === seen && !state.warnings.length) return;
    const changed = stamp !== seen;
    seen = stamp;
    try {
      const hosts = parseHosts(text);
      const before = state.warnings.join("\n");
      state.warnings = apply(hosts);
      Object.assign(state, { appliedAt: new Date().toISOString(), entries: hosts.length, error: null });
      if (changed || before !== state.warnings.join("\n")) onChange?.(state);
    } catch (err) {
      state.error = (err as Error).message;
      onChange?.(state);
    }
  };
  read();
  const timer = setInterval(read, everyMs);
  timer.unref();
  return { state, read, stop: () => clearInterval(timer) };
}
