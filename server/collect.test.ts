import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fingerprint } from "./collect.ts";
import { parseHosts } from "./hosts.ts";
import { rule, startApp } from "./test-app.ts";

const VERSION = "0.1.0";
const HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFmXq7hWQvK1eF4s3n0q6X8b9mZ2nqJ8V7cJq3s1kR2x";
const OTHER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9w3m0yQ1L7r2hY8kP4oX6n5aB1cD2eF3gH4iJ5kL6m";
const CA_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl OpenAsy siem-agent CA";
const CURSOR = "s=abc;i=1f;b=00;m=12;t=34;x=56";
const REPORT = (version = VERSION) => ({
  version,
  caPublicKey: CA_KEY,
  keyPublicKey: HOST_KEY.replace("Fm", "Hm"),
  setup: {
    sshdConfig: "TrustedUserCAKeys /etc/ssh/openasy_ca.pub\n",
    hostSetup: "usermod -aG systemd-journal openasy\n",
    authorizedKey: "restrict ssh-ed25519 AAAA",
  },
  running: 0,
});

let app: Awaited<ReturnType<typeof startApp>>;
const json = async (res: Response) => (await res.json()) as any;
const post = (path: string, body?: unknown, headers: Record<string, string> = {}) =>
  fetch(app.base + path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const asAgent = (secret: string) => (path: string, body: unknown) => post(path, body, { authorization: `Bearer ${secret}` });
const fromFile = (yaml: string) => app.collector.syncFile(parseHosts(yaml));

/** A stand-in siem-agent: each round asks for jobs and answers them the way the real one does. */
function fakeAgent(secret: string) {
  const call = asAgent(secret);
  const hosts = new Map<string, { key: string; events: Array<Record<string, unknown>>; cursor?: string; fail?: { kind: string; message: string } }>();
  return {
    hosts,
    async round(version = VERSION) {
      const res = await call("/api/v1/agent/work", REPORT(version));
      if (!res.ok) return { status: res.status, jobs: [] as any[] };
      const { jobs } = await json(res);
      for (const j of jobs) {
        const h = hosts.get(j.target.address)!;
        const base = { jobId: j.id, hostId: j.hostId };
        if (h.fail) await call("/api/v1/agent/results", { ...base, ok: false, error: h.fail });
        else if (j.action === "host-key") await call("/api/v1/agent/results", { ...base, ok: true, hostKeys: [h.key] });
        else if (!j.target.hostKeys.includes(h.key))
          await call("/api/v1/agent/results", { ...base, ok: false, error: { kind: "host-key-changed", message: "changed" }, hostKeys: [h.key] });
        else await call("/api/v1/agent/results", { ...base, ok: true, events: h.events, cursor: { journal: h.cursor ?? null }, more: false, unreadable: [] });
      }
      return { status: res.status, jobs };
    },
  };
}

beforeAll(async () => {
  app = await startApp({ version: VERSION });
  await app.addRule(rule("Failed SSH login", "s:\n  source: sshd\n  message|contains: Failed password\ncondition: s", "medium"));
});
afterAll(() => app.close());

describe("collection by siem-agent (ADR 0040, 0031)", () => {
  let agent: ReturnType<typeof fakeAgent>;
  let agentId = "";
  let hostId = "";

  it("adds agents, enrols each once with its token, and shows what hosts need", async () => {
    const created = await app.admin("/api/v1/agents", { method: "POST", body: JSON.stringify({ name: "dc-1" }) });
    expect(created.status).toBe(201);
    const { agent: a, enrollToken } = await json(created);
    expect(enrollToken).toMatch(/^oie_/);
    expect((await app.admin(`/api/v1/agents/${a.id}/setup`)).status).toBe(409);
    expect((await post("/api/v1/agent/enroll", { token: "oie_wrong", ...REPORT() })).status).toBe(401);
    expect((await post("/api/v1/agent/enroll", { token: enrollToken, ...REPORT(), caPublicKey: "nope" })).status).toBe(422);
    const enrolled = await json(await post("/api/v1/agent/enroll", { token: enrollToken, ...REPORT() }));
    expect(enrolled.secret).toMatch(/^oia_/);
    expect((await post("/api/v1/agent/enroll", { token: enrollToken, ...REPORT() })).status).toBe(401);
    expect(await json(await app.admin(`/api/v1/agents/${a.id}/setup`))).toMatchObject({
      caPublicKey: CA_KEY,
      caFingerprint: fingerprint(CA_KEY),
      hostSetup: expect.stringContaining("systemd-journal"),
    });
    // A new token: the old secret stops working.
    const again = await json(await app.admin(`/api/v1/agents/${a.id}/enroll-token`, { method: "POST" }));
    expect(again.agent.status).toBe("waiting-to-enrol");
    expect((await asAgent(enrolled.secret)("/api/v1/agent/work", REPORT())).status).toBe(401);
    const second = await json(await post("/api/v1/agent/enroll", { token: again.enrollToken, ...REPORT() }));
    agent = fakeAgent(second.secret);
    agentId = a.id;
    expect((await json(await app.admin("/api/v1/agents"))).agents[0]).toMatchObject({ name: "dc-1", status: "online", version: VERSION });
  });

  it("reads the hosts of the hosts file once their key is accepted", async () => {
    agent.hosts.set("10.0.0.5", { key: HOST_KEY, events: [], cursor: CURSOR });
    expect(fromFile("hosts:\n  - { name: web-1, address: 10.0.0.5 }\n  - { name: inner, address: 10.0.0.6, jump: web-1 }\n")).toEqual([
      "inner: siem reaches hosts directly, not through a jump host like web-1; it is left out.",
    ]);
    const list = await json(await app.admin("/api/v1/hosts"));
    expect(list.hosts).toEqual([expect.objectContaining({ name: "web-1", status: "new", agent: { id: agentId, name: "dc-1" } })]);
    hostId = list.hosts[0].id;
    expect((await app.admin(`/api/v1/hosts/${hostId}/read`, { method: "POST" })).status).toBe(409);

    await agent.round();
    expect(await json(await app.admin(`/api/v1/hosts/${hostId}`))).toMatchObject({
      status: "host-key-pending",
      pendingHostKeys: [{ fingerprint: fingerprint(HOST_KEY) }],
    });
    const accept = (fp: string) => app.admin(`/api/v1/hosts/${hostId}/host-key/accept`, { method: "POST", body: JSON.stringify({ fingerprint: fp }) });
    expect((await accept("SHA256:nope")).status).toBe(422);
    expect((await json(await accept(fingerprint(HOST_KEY)))).status).toBe("pending");
  });

  it("keeps the events under the host's name, runs the rules over them, then moves the cursor", async () => {
    agent.hosts.get("10.0.0.5")!.events = [
      {
        time: new Date().toISOString(),
        host: "what-the-host-says",
        source: "sshd",
        message: "Failed password for root from 203.0.113.7 port 22 ssh2",
        user: "root",
      },
      { time: new Date().toISOString(), source: "systemd", message: "Started Daily apt upgrade." },
    ];
    const { jobs } = await agent.round();
    expect(jobs).toEqual([expect.objectContaining({ action: "read", cursor: { journal: null } })]);
    const events = (await json(await app.admin("/api/v1/events?host=web-1"))).events as Array<Record<string, any>>;
    expect(events.map((e) => e.source).sort()).toEqual(["sshd", "systemd"]);
    expect((await json(await app.admin("/api/v1/signals?status=open"))).signals).toEqual([
      expect.objectContaining({ host: "web-1", rule: expect.objectContaining({ title: "Failed SSH login" }) }),
    ]);
    expect(await json(await app.admin(`/api/v1/hosts/${hostId}`))).toMatchObject({ status: "ok", eventsIn: 2 });
    // The next read starts where this one stopped.
    expect((await app.admin(`/api/v1/hosts/${hostId}/read`, { method: "POST" })).status).toBe(200);
    expect((await agent.round()).jobs[0].cursor).toEqual({ journal: CURSOR });
  });

  it("stops a host that presents another key until an admin accepts it, and refuses another version", async () => {
    agent.hosts.get("10.0.0.5")!.key = OTHER_KEY;
    await app.admin(`/api/v1/hosts/${hostId}/read`, { method: "POST" });
    await agent.round();
    expect(await json(await app.admin(`/api/v1/hosts/${hostId}`))).toMatchObject({
      status: "host-key-changed",
      pendingHostKeys: [{ fingerprint: fingerprint(OTHER_KEY) }],
    });
    expect((await agent.round()).jobs).toEqual([]);
    expect((await agent.round("0.0.1")).status).toBe(409);
    expect((await json(await app.admin("/api/v1/agents"))).agents[0].lastError).toBe(`siem-agent 0.0.1 does not match siem ${VERSION}`);
  });

  it("trusts a key the hosts file vouches for, says why a read failed, and lets hosts go with the file", async () => {
    fromFile(`hosts:\n  - { name: web-1, address: 10.0.0.9, hostKey: '${fingerprint(HOST_KEY)}' }\n`);
    agent.hosts.set("10.0.0.9", { key: HOST_KEY, events: [], fail: undefined });
    await agent.round();
    expect(await json(await app.admin(`/api/v1/hosts/${hostId}`))).toMatchObject({ status: "pending", hostKeys: [{ fingerprint: fingerprint(HOST_KEY) }] });
    agent.hosts.get("10.0.0.9")!.fail = { kind: "unreachable", message: "ssh: connect to host 10.0.0.9 port 22: Connection refused" };
    await agent.round();
    expect((await json(await app.admin(`/api/v1/hosts/${hostId}`))).statusDetail).toContain("Connection refused");
    expect((await app.admin(`/api/v1/agents/${agentId}`, { method: "DELETE" })).status).toBe(409);
    fromFile("hosts: []\n");
    expect((await app.admin(`/api/v1/hosts/${hostId}`)).status).toBe(404);
    expect((await app.admin(`/api/v1/agents/${agentId}`, { method: "DELETE" })).status).toBe(204);
  });
});
