// Opens an incident in OpenAsy Incidents for what this product finds (ADR 0041, 0023). Incidents takes them over its
// API with a token that has the editor role there. The product names itself and its own id for the problem in
// `external`, so asking again for the same id is the same incident, never a second one. Calls give up after 10
// seconds; the caller keeps what could not be sent and tries again later.

export interface IncidentsLinkOptions {
  /** Where this product calls Incidents, such as http://incidents:8080 in the same compose network. */
  url: string;
  /** An API token of Incidents with the editor role: it opens and updates incidents and does nothing else. */
  token: string;
  /** Where people open Incidents, for links; the url when not set. */
  publicUrl?: string;
  /** This product's id, such as siem: the incident's product and the source of its external id. */
  product: string;
  /** For tests: the HTTP client. */
  fetch?: typeof fetch;
}

export interface OpenedIncident {
  id: string;
  /** What people say aloud, such as INC-12. */
  key: string;
  /** The incident's page in Incidents. */
  url: string;
  /** False when Incidents had it already: it added a note instead. */
  created: boolean;
}

export type Severity = "critical" | "high" | "medium" | "low";

export function createIncidentsLink(o: IncidentsLinkOptions) {
  const http = o.fetch ?? fetch;
  const base = o.url.replace(/\/$/, "");
  const page = (o.publicUrl ?? o.url).replace(/\/$/, "");

  async function post(path: string, body: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await http(`${base}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${o.token}`, "content-type": "application/json", "user-agent": `openasy-${o.product}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const detail = ((await res.json().catch(() => ({}))) as { detail?: unknown }).detail;
      throw new Error(
        res.status === 401
          ? "Incidents refused the token: make a new one under Settings, API tokens in Incidents."
          : res.status === 403
            ? "The token may not open incidents: it needs the editor role in Incidents."
            : `Incidents answered ${res.status}${typeof detail === "string" ? `: ${detail}` : "."}`,
      );
    }
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  }

  return {
    /** Opens the incident for `reference`, with a link back to where it was found when it is new. */
    async open(i: {
      reference: string;
      title: string;
      severity: Severity;
      summary: string;
      evidence?: { title: string; url: string };
    }): Promise<OpenedIncident> {
      const res = await post("/api/v1/incidents", {
        title: i.title.slice(0, 200),
        severity: i.severity,
        summary: i.summary.slice(0, 5000),
        products: [o.product],
        external: { source: o.product, reference: i.reference.slice(0, 256) },
      });
      const id = res.body.id as string;
      const key = res.body.key as string;
      const created = res.status === 201;
      if (created && i.evidence)
        await post(`/api/v1/incidents/${encodeURIComponent(id)}/evidence`, { title: i.evidence.title.slice(0, 200), url: i.evidence.url, source: o.product });
      return { id, key, url: `${page}/incidents/${encodeURIComponent(key)}`, created };
    },

    /** Adds a note to the incident's timeline, such as that the problem ended. */
    async note(id: string, text: string): Promise<void> {
      await post(`/api/v1/incidents/${encodeURIComponent(id)}/timeline`, { kind: "note", text: text.slice(0, 2000) });
    },
  };
}

export type IncidentsLink = ReturnType<typeof createIncidentsLink>;
