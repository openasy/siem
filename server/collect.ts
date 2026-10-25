// Collection by siem-agent (ADR 0040, 0031): agents enrolled here read the security events of the hosts in the
// install's hosts file over SSH and send them back, and they go through the same rules as events sent by a shipper.
// siem holds no SSH key and sends no commands: an agent asks for jobs ("read this host from this cursor"), runs the
// script built into it and sends the events. The pattern is Logs' (ADR 0035), without container logs.
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { HostEntry } from "./hosts.ts";
import { log } from "./log.ts";
import { MAX_EVENTS, SiemError } from "./siem.ts";

interface AgentRow {
  id: string;
  name: string;
  enroll_token_hash: string | null;
  enroll_expires_at: string | null;
  secret_hash: string | null;
  version: string | null;
  ca_public_key: string | null;
  key_public_key: string | null;
  setup: string | null;
  last_seen_at: string | null;
  last_error: string | null;
  created_at: string;
}

interface HostRow {
  id: string;
  name: string;
  agent_id: string;
  address: string;
  port: number;
  ssh_user: string;
  auth: "certificate" | "key";
  key_file: string | null;
  file_host_key: string | null;
  interval_seconds: number;
  host_keys: string;
  pending_host_keys: string;
  status: string;
  status_detail: string | null;
  unreadable: string;
  journal_cursor: string | null;
  events_in: number;
  last_attempt_at: string | null;
  last_success_at: string | null;
  read_requested: number;
  key_requested: number;
  lease_until: string | null;
  created_at: string;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const HOST_KEY = /^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,2}$/;
/** journalctl cursors: s=...;i=...;b=...;m=...;t=...;x=... */
const CURSOR = /^[a-z]=[0-9a-f]+(;[a-z]=[0-9a-f]+){0,7}$/;
const JOB_LEASE_MS = 2 * 60_000;
const ENROLL_TTL_MS = 7 * 86_400_000;
const AGENT_OFFLINE_MS = 2 * 60_000;
/** Events in one result; the agent reads fewer and asks again at once when more are waiting. */
export const MAX_RESULT_EVENTS = 10_000;
const FAILURES = new Set(["unreachable", "auth-failed", "host-key-changed", "host-key-unknown", "timeout", "error", "invalid-job"]);

const bad = (detail: string) => new SiemError(422, "invalid-body", detail);
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** SHA256:... as OpenSSH prints it. */
export function fingerprint(keyLine: string): string {
  const blob = keyLine.trim().split(/\s+/)[1] ?? "";
  return `SHA256:${createHash("sha256").update(Buffer.from(blob, "base64")).digest("base64").replace(/=+$/, "")}`;
}

export interface CollectOptions {
  /** siem's version: an agent of another version is refused (ADR 0019). */
  version: string;
  /** Keeps events and runs the rules over them, as POST /api/v1/events does. */
  ingest: (events: unknown[]) => unknown;
  /** For tests. */
  clock?: () => number;
}

export function createCollector(db: DatabaseSync, o: CollectOptions) {
  const now = o.clock ?? Date.now;
  const iso = (t = now()) => new Date(t).toISOString();

  // ---- Agents -------------------------------------------------------------------------------------------------------

  const agentRow = (id: string) => db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as AgentRow | undefined;
  const requireAgent = (id: string) => {
    const a = agentRow(id);
    if (!a) throw new SiemError(404, "not-found", "No such agent.");
    return a;
  };

  function toAgent(a: AgentRow) {
    const online = !!a.last_seen_at && Date.parse(a.last_seen_at) + AGENT_OFFLINE_MS > now();
    return {
      id: a.id,
      name: a.name,
      status: (!a.secret_hash ? "waiting-to-enrol" : online ? (a.version === o.version ? "online" : "version-mismatch") : "offline") as
        "waiting-to-enrol" | "online" | "version-mismatch" | "offline",
      version: a.version,
      caFingerprint: a.ca_public_key ? fingerprint(a.ca_public_key) : null,
      lastSeenAt: a.last_seen_at,
      lastError: a.last_error,
      hosts: (db.prepare("SELECT COUNT(*) AS n FROM hosts WHERE agent_id = ?").get(a.id) as { n: number }).n,
      createdAt: a.created_at,
    };
  }

  function newEnrollToken(id: string) {
    const token = `oie_${randomBytes(24).toString("base64url")}`;
    db.prepare("UPDATE agents SET enroll_token_hash = ?, enroll_expires_at = ? WHERE id = ?").run(sha256(token), iso(now() + ENROLL_TTL_MS), id);
    return { enrollToken: token, enrollExpiresAt: iso(now() + ENROLL_TTL_MS) };
  }

  function createAgent(b: Record<string, unknown>) {
    if (Object.keys(b).some((k) => k !== "name")) throw bad("Expected { name }.");
    if (typeof b.name !== "string" || !NAME.test(b.name)) throw bad("name is letters, digits, dots, dashes and underscores, up to 63.");
    if (db.prepare("SELECT 1 FROM agents WHERE name = ?").get(b.name)) throw new SiemError(409, "conflict", `An agent named ${b.name} exists.`);
    const id = randomUUID();
    db.prepare("INSERT INTO agents (id, name, created_at) VALUES (?, ?, ?)").run(id, b.name, iso());
    return { agent: toAgent(requireAgent(id)), ...newEnrollToken(id) };
  }

  /** A new one-time token; the agent's secret and CA are forgotten, so it enrols again with what it has now. */
  function reEnroll(id: string) {
    requireAgent(id);
    db.prepare("UPDATE agents SET secret_hash = NULL, ca_public_key = NULL WHERE id = ?").run(id);
    return { agent: toAgent(requireAgent(id)), ...newEnrollToken(id) };
  }

  function deleteAgent(id: string) {
    requireAgent(id);
    if (db.prepare("SELECT 1 FROM hosts WHERE agent_id = ?").get(id))
      throw new SiemError(409, "conflict", "Hosts are read by this agent. Name another agent for them in the hosts file first.");
    db.prepare("DELETE FROM agents WHERE id = ?").run(id);
  }

  /** What an admin puts on a host for this agent: its CA, and the commands that let the account read the journal. */
  function agentSetup(id: string) {
    const a = requireAgent(id);
    if (!a.setup || !a.ca_public_key) throw new SiemError(409, "conflict", "The agent has not enrolled yet. Start it with its enrolment token.");
    return {
      agent: toAgent(a),
      caPublicKey: a.ca_public_key,
      caFingerprint: fingerprint(a.ca_public_key),
      keyPublicKey: a.key_public_key,
      ...(JSON.parse(a.setup) as Record<string, string>),
    };
  }

  function checkReport(b: Record<string, unknown>) {
    const isKey = (v: unknown) => typeof v === "string" && HOST_KEY.test(v.trim().split(/\s+/).slice(0, 2).join(" "));
    if (typeof b.version !== "string" || b.version.length > 32) throw bad("version is required.");
    if (!isKey(b.caPublicKey)) throw bad("caPublicKey is an OpenSSH public key.");
    if (!isKey(b.keyPublicKey)) throw bad("keyPublicKey is an OpenSSH public key.");
    const s = b.setup as Record<string, unknown> | undefined;
    if (!s || ["sshdConfig", "hostSetup", "authorizedKey"].some((k) => typeof s[k] !== "string" || (s[k] as string).length > 64_000))
      throw bad("setup holds sshdConfig, hostSetup and authorizedKey.");
    return {
      version: b.version,
      caPublicKey: (b.caPublicKey as string).trim(),
      keyPublicKey: (b.keyPublicKey as string).trim(),
      setup: JSON.stringify({ sshdConfig: s.sshdConfig, hostSetup: s.hostSetup, authorizedKey: s.authorizedKey }),
    };
  }

  function enroll(b: Record<string, unknown>) {
    const token = typeof b.token === "string" ? b.token : "";
    const a = db.prepare("SELECT * FROM agents WHERE enroll_token_hash = ?").get(sha256(token)) as AgentRow | undefined;
    if (!a || !a.enroll_expires_at || a.enroll_expires_at <= iso())
      throw new SiemError(401, "invalid-token", "The enrolment token is unknown, used or expired. Create a new one under Agents.");
    const r = checkReport(b);
    const secret = `oia_${randomBytes(32).toString("base64url")}`;
    db.prepare(
      "UPDATE agents SET enroll_token_hash = NULL, enroll_expires_at = NULL, secret_hash = ?, version = ?, ca_public_key = ?, key_public_key = ?, setup = ?, last_seen_at = ?, last_error = NULL WHERE id = ?",
    ).run(sha256(secret), r.version, r.caPublicKey, r.keyPublicKey, r.setup, iso(), a.id);
    log("info", "agent enrolled", { agent: a.name, version: r.version, ca: fingerprint(r.caPublicKey) });
    return { agentId: a.id, secret };
  }

  function agentBySecret(header: string | undefined): AgentRow {
    const secret = header?.startsWith("Bearer oia_") ? header.slice(7) : "";
    const a = secret ? (db.prepare("SELECT * FROM agents WHERE secret_hash = ?").get(sha256(secret)) as AgentRow | undefined) : undefined;
    if (!a) throw new SiemError(401, "invalid-token", "Unknown agent secret. Enrol the agent again under Agents.");
    return a;
  }

  // ---- Hosts --------------------------------------------------------------------------------------------------------

  const hostRow = (id: string) => db.prepare("SELECT * FROM hosts WHERE id = ?").get(id) as HostRow | undefined;
  const requireHost = (id: string) => {
    const h = hostRow(id);
    if (!h) throw new SiemError(404, "not-found", "No such host.");
    return h;
  };
  const keyPinned = (h: HostRow) => JSON.parse(h.host_keys).length > 0 && h.status !== "host-key-changed" && h.status !== "host-key-pending";

  function work(a: AgentRow, b: Record<string, unknown>) {
    const r = checkReport(b);
    // ADR 0019: an agent always has the same version as its product.
    if (r.version !== o.version) {
      db.prepare("UPDATE agents SET version = ?, last_seen_at = ?, last_error = ? WHERE id = ?").run(
        r.version,
        iso(),
        `siem-agent ${r.version} does not match siem ${o.version}`,
        a.id,
      );
      throw new SiemError(409, "conflict", `siem-agent ${r.version} does not match siem ${o.version}; install siem-agent ${o.version}`);
    }
    if (a.ca_public_key && a.ca_public_key !== r.caPublicKey)
      throw new SiemError(409, "conflict", "This agent's CA changed since it enrolled. Enrol it again under Agents.");
    db.prepare("UPDATE agents SET version = ?, key_public_key = ?, setup = ?, last_seen_at = ?, last_error = NULL WHERE id = ?").run(
      r.version,
      r.keyPublicKey,
      r.setup,
      iso(),
      a.id,
    );

    const t = now();
    const free = (h: HostRow) => !h.lease_until || Date.parse(h.lease_until) <= t;
    const hosts = (db.prepare("SELECT * FROM hosts WHERE agent_id = ?").all(a.id) as unknown as HostRow[]).filter(free);
    const keyJobs = hosts.filter((h) => h.key_requested === 1);
    const due = hosts.filter(
      (h) =>
        h.key_requested === 0 &&
        keyPinned(h) &&
        (h.read_requested === 1 || !h.last_attempt_at || Date.parse(h.last_attempt_at) + h.interval_seconds * 1000 <= t),
    );
    const jobs = [...keyJobs.map((h) => ({ h, action: "host-key" as const })), ...due.map((h) => ({ h, action: "read" as const }))].slice(0, 64);
    const leaseKey = db.prepare("UPDATE hosts SET lease_until = ? WHERE id = ?");
    const leaseRead = db.prepare("UPDATE hosts SET lease_until = ?, last_attempt_at = ?, read_requested = 0 WHERE id = ?");
    return {
      jobs: jobs.map(({ h, action }) => {
        if (action === "read") leaseRead.run(iso(t + JOB_LEASE_MS), iso(t), h.id);
        else leaseKey.run(iso(t + JOB_LEASE_MS), h.id);
        return {
          id: randomUUID(),
          hostId: h.id,
          action,
          target: {
            address: h.address,
            port: h.port,
            user: h.ssh_user,
            hostKeys: JSON.parse(h.host_keys) as string[],
            auth: h.auth,
            ...(h.auth === "key" && h.key_file && { keyFile: h.key_file }),
          },
          cursor: { journal: h.journal_cursor },
        };
      }),
    };
  }

  /** A host's events, a host key it presents, or why it could not be read. The cursor moves once the events are kept. */
  function result(a: AgentRow, b: Record<string, unknown>) {
    const h = typeof b.hostId === "string" ? hostRow(b.hostId) : undefined;
    if (!h || h.agent_id !== a.id) throw new SiemError(404, "not-found", "No such host for this agent.");
    db.prepare("UPDATE hosts SET lease_until = NULL WHERE id = ?").run(h.id);
    const keys = b.hostKeys;
    const keyList =
      Array.isArray(keys) && keys.length > 0 && keys.length <= 8 && keys.every((k) => typeof k === "string" && HOST_KEY.test(k))
        ? (keys as string[])
        : undefined;
    if (b.ok === true && keyList && b.events === undefined) {
      // The hosts file vouches for a key with its fingerprint (ADR 0052): that key is pinned without an admin.
      const vouched = h.file_host_key && h.file_host_key !== "first" ? keyList.find((k) => fingerprint(k) === h.file_host_key) : undefined;
      // hostKey: first trusts the keys the host presents the first time, and none other after (ssh's accept-new).
      const firstSeen = h.file_host_key === "first" && (JSON.parse(h.host_keys) as string[]).length === 0;
      if (firstSeen || vouched) {
        db.prepare(
          "UPDATE hosts SET key_requested = 0, host_keys = ?, pending_host_keys = '[]', status = 'pending', status_detail = NULL, read_requested = 1 WHERE id = ?",
        ).run(JSON.stringify(firstSeen ? keyList : [vouched]), h.id);
        log("info", "host key trusted from the hosts file", { host: h.name, fingerprints: (firstSeen ? keyList : [vouched!]).map(fingerprint) });
        return { status: "accepted" };
      }
      const pinned = JSON.parse(h.host_keys) as string[];
      const same = pinned.length > 0 && keyList.every((k) => pinned.includes(k));
      db.prepare("UPDATE hosts SET key_requested = 0, pending_host_keys = ?, status = ?, status_detail = ? WHERE id = ?").run(
        JSON.stringify(same ? [] : keyList),
        same ? (h.status === "host-key-changed" ? "pending" : h.status) : pinned.length ? "host-key-changed" : "host-key-pending",
        same
          ? h.status_detail
          : h.file_host_key && h.file_host_key !== "first"
            ? `The host presents a key that is not ${h.file_host_key} from the hosts file. Check the host, then fix hostKey in the file.`
            : pinned.length
              ? "The host presents a different key. Check it on the host, then accept it."
              : "Check the fingerprint on the host, then accept it.",
        h.id,
      );
      return { status: "accepted" };
    }
    if (b.ok === true && b.events !== undefined) {
      if (!keyPinned(h)) throw new SiemError(409, "conflict", "The host key is not accepted; events are not kept.");
      const raw = b.events;
      if (!Array.isArray(raw) || raw.length > MAX_RESULT_EVENTS) throw bad(`events is a list of up to ${MAX_RESULT_EVENTS} events.`);
      // The host's name from the hosts file, not what the host calls itself: rules, signals and the screens use it.
      const events = raw.map((e) => (e && typeof e === "object" && !Array.isArray(e) ? { ...(e as Record<string, unknown>), host: h.name } : e));
      for (let i = 0; i < events.length; i += MAX_EVENTS) o.ingest(events.slice(i, i + MAX_EVENTS));
      const cursor = (b.cursor ?? {}) as { journal?: unknown };
      const journal = typeof cursor.journal === "string" && CURSOR.test(cursor.journal) ? cursor.journal : h.journal_cursor;
      const unreadable = Array.isArray(b.unreadable) ? b.unreadable.filter((u): u is string => typeof u === "string").slice(0, 16) : [];
      db.prepare(
        "UPDATE hosts SET status = 'ok', status_detail = NULL, unreadable = ?, journal_cursor = ?, events_in = events_in + ?, last_success_at = ?, read_requested = ? WHERE id = ?",
      ).run(JSON.stringify(unreadable), journal, events.length, iso(), b.more === true ? 1 : 0, h.id);
      return { status: "accepted" };
    }
    const e = b.error as { kind?: unknown; message?: unknown } | undefined;
    if (b.ok !== false || !e || typeof e.kind !== "string" || !FAILURES.has(e.kind) || typeof e.message !== "string")
      throw bad("Expected events, hostKeys, or an error with kind and message.");
    const message = e.message.slice(0, 1000);
    if (e.kind === "host-key-changed") {
      db.prepare("UPDATE hosts SET status = 'host-key-changed', status_detail = ?, pending_host_keys = ? WHERE id = ?").run(
        "The host key changed. Check the host, then accept the new key.",
        JSON.stringify(keyList ?? []),
        h.id,
      );
    } else {
      db.prepare("UPDATE hosts SET status = ?, status_detail = ? WHERE id = ?").run(e.kind === "host-key-unknown" ? "unreachable" : e.kind, message, h.id);
    }
    log("warn", "host read failed", { host: h.name, kind: e.kind, error: message });
    return { status: "accepted" };
  }

  function toHost(h: HostRow) {
    const agent = agentRow(h.agent_id)!;
    return {
      id: h.id,
      name: h.name,
      agent: { id: agent.id, name: agent.name },
      // A fingerprint the file trusts; first is not one, and its key is accepted like any other once it changes.
      fileHostKey: h.file_host_key === "first" ? null : h.file_host_key,
      address: h.address,
      port: h.port,
      user: h.ssh_user,
      auth: h.auth,
      intervalSeconds: h.interval_seconds,
      hostKeys: (JSON.parse(h.host_keys) as string[]).map((k) => ({ type: k.split(" ")[0]!, fingerprint: fingerprint(k) })),
      pendingHostKeys: (JSON.parse(h.pending_host_keys) as string[]).map((k) => ({ type: k.split(" ")[0]!, fingerprint: fingerprint(k) })),
      status: h.status,
      statusDetail: h.status_detail,
      unreadable: JSON.parse(h.unreadable) as string[],
      eventsIn: h.events_in,
      lastAttemptAt: h.last_attempt_at,
      lastSuccessAt: h.last_success_at,
      createdAt: h.created_at,
    };
  }

  function requestHostKey(id: string) {
    requireHost(id);
    db.prepare("UPDATE hosts SET key_requested = 1, lease_until = NULL WHERE id = ?").run(id);
    return toHost(requireHost(id));
  }

  function acceptHostKey(id: string, fp: unknown) {
    const h = requireHost(id);
    if (h.file_host_key && h.file_host_key !== "first")
      throw new SiemError(409, "conflict", "Its key is the one hostKey names in the hosts file (OPENASY_HOSTS); change hostKey there to trust another.");
    const key = (JSON.parse(h.pending_host_keys) as string[]).find((k) => fingerprint(k) === fp);
    if (typeof fp !== "string" || !key) throw bad("fingerprint must be one of the pending host keys, as SHA256:...");
    db.prepare(
      "UPDATE hosts SET host_keys = ?, pending_host_keys = '[]', status = 'pending', status_detail = NULL, read_requested = 1, lease_until = NULL WHERE id = ?",
    ).run(JSON.stringify([key]), id);
    return toHost(requireHost(id));
  }

  function requestRead(id: string) {
    const h = requireHost(id);
    if (!keyPinned(h)) throw new SiemError(409, "conflict", "Accept the host key first.");
    db.prepare("UPDATE hosts SET read_requested = 1 WHERE id = ?").run(id);
    return toHost(requireHost(id));
  }

  /**
   * Makes the hosts match the hosts file (ADR 0052): adds, changes and removes them. siem reaches hosts directly, so one
   * behind a jump host is left out with a warning. An entry that cannot be added yet, such as one whose agent is not
   * there, is a warning. A new address, port or agent, or another hostKey than the pinned key, is a new trust decision.
   * Returns what to fix.
   */
  function syncFile(entries: HostEntry[]): string[] {
    const warnings: string[] = [];
    const agents = db.prepare("SELECT id, name FROM agents").all() as Array<{ id: string; name: string }>;
    for (const e of entries) {
      if (e.jump) {
        warnings.push(`${e.name}: siem reaches hosts directly, not through a jump host like ${e.jump}; it is left out.`);
        continue;
      }
      let agentId: string | undefined;
      if (e.agent) {
        agentId = agents.find((x) => x.name === e.agent)?.id;
        if (!agentId) warnings.push(`${e.name}: no agent is named ${e.agent}; it is added once one is.`);
      } else if (agents.length === 1) agentId = agents[0]!.id;
      else
        warnings.push(
          agents.length
            ? `${e.name}: name the agent that reaches it with agent:, as there are ${agents.length}.`
            : `${e.name}: it is added once an agent is, under Agents.`,
        );
      if (!agentId) continue;
      const h = db.prepare("SELECT * FROM hosts WHERE name = ?").get(e.name) as HostRow | undefined;
      if (!h) {
        db.prepare(
          "INSERT INTO hosts (id, name, agent_id, address, port, ssh_user, auth, key_file, file_host_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(randomUUID(), e.name, agentId, e.address, e.port, e.user, e.auth, e.keyFile, e.hostKey, iso());
        continue;
      }
      const pinned = JSON.parse(h.host_keys) as string[];
      const moved = e.address !== h.address || e.port !== h.port || agentId !== h.agent_id;
      const vouchesOther =
        !!e.hostKey && e.hostKey !== "first" && e.hostKey !== h.file_host_key && pinned.length > 0 && !pinned.some((k) => fingerprint(k) === e.hostKey);
      db.prepare("UPDATE hosts SET agent_id = ?, address = ?, port = ?, ssh_user = ?, auth = ?, key_file = ?, file_host_key = ? WHERE id = ?").run(
        agentId,
        e.address,
        e.port,
        e.user,
        e.auth,
        e.keyFile,
        e.hostKey,
        h.id,
      );
      if (moved || vouchesOther)
        db.prepare(
          "UPDATE hosts SET host_keys = '[]', pending_host_keys = '[]', status = 'new', status_detail = NULL, key_requested = 1, lease_until = NULL WHERE id = ?",
        ).run(h.id);
      // A hostKey given now for a host whose key is not pinned yet: ask for the key again, to trust it if it matches.
      else if (e.hostKey && e.hostKey !== h.file_host_key && !pinned.length)
        db.prepare("UPDATE hosts SET key_requested = 1, lease_until = NULL WHERE id = ?").run(h.id);
    }
    // Hosts that left the file go; events already kept stay until retention removes them.
    const named = new Set(entries.filter((e) => !e.jump).map((e) => e.name));
    for (const h of db.prepare("SELECT id, name FROM hosts").all() as Array<{ id: string; name: string }>) {
      if (!named.has(h.name)) db.prepare("DELETE FROM hosts WHERE id = ?").run(h.id);
    }
    return warnings;
  }

  return {
    listAgents: () => (db.prepare("SELECT * FROM agents ORDER BY name").all() as unknown as AgentRow[]).map(toAgent),
    agent: (id: string) => toAgent(requireAgent(id)),
    createAgent,
    reEnroll,
    deleteAgent,
    agentSetup,
    enroll,
    agentBySecret,
    work,
    result,
    listHosts: () => (db.prepare("SELECT * FROM hosts ORDER BY name").all() as unknown as HostRow[]).map(toHost),
    host: (id: string) => toHost(requireHost(id)),
    requestHostKey,
    acceptHostKey,
    requestRead,
    syncFile,
    /** For /metrics: agents by status, and hosts by status. */
    counts() {
      const agents: Record<string, number> = {};
      for (const a of (db.prepare("SELECT * FROM agents").all() as unknown as AgentRow[]).map(toAgent)) agents[a.status] = (agents[a.status] ?? 0) + 1;
      const hosts: Record<string, number> = {};
      for (const r of db.prepare("SELECT status, COUNT(*) AS n FROM hosts GROUP BY status").all() as Array<{ status: string; n: number }>)
        hosts[r.status] = r.n;
      return { agents, hosts };
    },
  };
}

export type Collector = ReturnType<typeof createCollector>;
