// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Level = "critical" | "high" | "medium" | "low";
export type Status = "new" | "investigating" | "closed" | "false-positive";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Summary {
  events: number;
  eventsLastDay: number;
  lastEventAt: string | null;
  rules: { total: number; enabled: number; failing: number };
  open: Record<Level, number>;
}

export interface Event {
  id: number;
  time: string;
  host: string | null;
  source: string | null;
  message: string | null;
  fields: Record<string, string | number | boolean | null>;
  receivedAt: string;
}

export interface Rule {
  id: string;
  title: string;
  level: Level;
  enabled: boolean;
  description: string | null;
  tags: string[];
  source: string;
  matches: number;
  lastMatchAt: string | null;
  lastError: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface RuleTest {
  rule: { title: string; level: Level };
  evaluated: number;
  matches: number;
  hosts: number;
  events: Event[];
}

export interface Signal {
  id: string;
  rule: { id: string | null; title: string };
  severity: Level;
  host: string;
  status: Status;
  reason: string | null;
  changedBy: string | null;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface SignalDetail extends Signal {
  events: Event[];
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin", headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers } });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
