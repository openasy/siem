import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createIncidentsLink } from "./incidents.ts";
import { FAILED_LOGIN, MIMIKATZ, startApp } from "./test-app.ts";

const TOKEN = "oa_incidents_editor";

/** Incidents as siem sees it: one incident per external id, a 200 when it is asked again, and evidence on it. */
function fakeIncidents() {
  const incidents: Array<{ id: string; key: string; body: Record<string, any>; evidence: Array<Record<string, unknown>> }> = [];
  let down = false;
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
    const send = (status: number, b: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(b));
    if (down) return send(503, { detail: "Starting." });
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { detail: "No." });
    if (req.method === "POST" && req.url === "/api/v1/incidents") {
      const same = incidents.find((i) => i.body.external.reference === body.external.reference && i.body.external.source === body.external.source);
      if (same) return send(200, { id: same.id, key: same.key });
      const i = { id: `id-${incidents.length + 1}`, key: `INC-${incidents.length + 1}`, body, evidence: [] };
      incidents.push(i);
      return send(201, { id: i.id, key: i.key });
    }
    const m = /^\/api\/v1\/incidents\/([^/]+)\/evidence$/.exec(req.url!);
    if (req.method === "POST" && m) {
      incidents.find((i) => i.id === m[1])!.evidence.push(body);
      return send(201, {});
    }
    send(404, {});
  });
  return { server, incidents, setDown: (v: boolean) => (down = v) };
}

const fake = fakeIncidents();
let app: Awaited<ReturnType<typeof startApp>>;
const json = async (res: Response) => (await res.json()) as any;
const signals = async () => (await json(await app.admin("/api/v1/signals?status=open"))).signals as Array<Record<string, any>>;

beforeAll(async () => {
  await new Promise<void>((r) => fake.server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(fake.server.address() as AddressInfo).port}`;
  app = await startApp({
    version: "0.1.0",
    siem: {
      incidents: {
        link: createIncidentsLink({ url, token: TOKEN, publicUrl: "https://incidents.example.com", product: "siem" }),
        minSeverity: "high",
        signalUrl: (id) => `https://siem.example.com/?signal=${id}`,
      },
    },
  });
  await app.addRule(FAILED_LOGIN);
  await app.addRule(MIMIKATZ);
});
afterAll(async () => {
  await app.close();
  await new Promise((r) => fake.server.close(r));
});

describe("incidents from signals (ADR 0041)", () => {
  it("opens one incident for a new signal at the severity set or above, with a link back to it", async () => {
    // Failed login is medium, below high: no incident.
    await app.send({ host: "web-1", message: "Failed password for root" });
    await app.send({ host: "dc-1", Image: "C:\\Tools\\mimikatz.exe", User: "alice" });
    await app.siem.deliverIncidents();
    expect(fake.incidents).toHaveLength(1);
    const [incident] = fake.incidents;
    expect(incident!.body).toEqual({
      title: "Credential dumping tool on dc-1",
      severity: "critical",
      summary: expect.stringContaining('the rule "Credential dumping tool" matched on dc-1'),
      products: ["siem"],
      external: { source: "siem", reference: expect.stringMatching(/^signal:/) },
    });
    const list = await signals();
    const dumping = list.find((s) => s.host === "dc-1")!;
    expect(incident!.evidence).toEqual([
      { title: "SIEM signal: Credential dumping tool on dc-1", url: `https://siem.example.com/?signal=${dumping.id}`, source: "siem" },
    ]);
    expect(dumping.incident).toEqual({ state: "opened", key: "INC-1", url: "https://incidents.example.com/incidents/INC-1", error: null });
    expect(list.find((s) => s.host === "web-1")!.incident).toBeNull();

    // More events of the same signal open nothing more.
    await app.send({ host: "dc-1", Image: "C:\\Tools\\mimikatz.exe", User: "bob" });
    await app.siem.deliverIncidents();
    expect(fake.incidents).toHaveLength(1);
  });

  it("keeps a signal waiting while Incidents is unreachable, says why, and opens it when it is back", async () => {
    fake.setDown(true);
    await app.send({ host: "dc-2", Image: "C:\\Tools\\mimikatz.exe", User: "alice" });
    await app.siem.deliverIncidents();
    const waiting = (await signals()).find((s) => s.host === "dc-2")!;
    expect(waiting.incident).toEqual({ state: "pending", key: null, url: null, error: "Incidents answered 503: Starting." });
    // Events are kept and answered whatever Incidents does.
    expect((await app.send({ host: "dc-2", message: "still here" })).status).toBe(202);

    fake.setDown(false);
    await app.siem.deliverIncidents();
    expect((await signals()).find((s) => s.host === "dc-2")!.incident).toMatchObject({ state: "opened", key: "INC-2", error: null });
  });

  it("gives up on a signal after a day, and says a refused token plainly", async () => {
    const bad = createIncidentsLink({ url: `http://127.0.0.1:${(fake.server.address() as AddressInfo).port}`, token: "wrong", product: "siem" });
    await expect(bad.open({ reference: "x", title: "x", severity: "low", summary: "" })).rejects.toThrow(/refused the token/);

    fake.setDown(true);
    await app.send({ host: "dc-3", Image: "C:\\Tools\\mimikatz.exe", User: "alice" });
    await app.siem.deliverIncidents();
    app.db.prepare("UPDATE signals SET first_seen = ? WHERE host = 'dc-3'").run(new Date(Date.now() - 2 * 86_400_000).toISOString());
    await app.siem.deliverIncidents();
    expect((await signals()).find((s) => s.host === "dc-3")!.incident).toMatchObject({ state: "failed", error: "Incidents answered 503: Starting." });
    fake.setDown(false);
  });
});
