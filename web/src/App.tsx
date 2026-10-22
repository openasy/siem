import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  Switch,
  SeverityBadge,
  StatusBadge,
  Tabs,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bell, FlaskConical, KeyRound, LogIn, LogOut, Plus, ScrollText, Settings2, ShieldCheck, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type Event, type Level, type ProductLink, type Rule, type RuleTest, type Signal, type SignalDetail, type Status, type Summary } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const PAGES = ["rules", "events", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "signals" | (typeof PAGES)[number] };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["signals", ...PAGES];
function parseRoute(path: string): Route {
  const [page] = path.replace(/^\//, "").split("/");
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "signals" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const LEVELS: Level[] = ["critical", "high", "medium", "low"];
const STATUS_LABEL: Record<Status, string> = { new: "New", investigating: "Investigating", closed: "Closed", "false-positive": "False positive" };

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function StatusChip({ status }: { status: Status }) {
  return <StatusBadge tone={status === "new" ? "danger" : status === "investigating" ? "warning" : "neutral"}>{STATUS_LABEL[status]}</StatusBadge>;
}

/** Fields of an event other than the four every event has, as a short list. */
function Fields({ e }: { e: Event }) {
  const entries = Object.entries(e.fields);
  if (!entries.length) return null;
  return (
    <dl className="siem-pairs text-xs">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-fg-muted">{k}</dt>
          <dd className="siem-wrap m-0 font-mono">{String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function EventLine({ e }: { e: Event }) {
  return (
    <li className="flex flex-col gap-1 rounded-md border border-line p-2">
      <span className="flex flex-wrap items-center gap-1.5 text-xs">
        <span className="text-fg-muted">{new Date(e.time).toLocaleString()}</span>
        {e.host && <Badge mono>{e.host}</Badge>}
        {e.source && <Badge>{e.source}</Badge>}
      </span>
      {e.message && <span className="siem-wrap text-sm">{e.message}</span>}
      <Fields e={e} />
    </li>
  );
}

// ---------------------------------------------------------------- Signals

function SignalPanel({ id, call, onClose, onChanged }: { id: string; call: Call; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const [signal, setSignal] = useState<SignalDetail>();
  const [deciding, setDeciding] = useState<Status | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const load = useCallback(() => void call<SignalDetail>(`/api/v1/signals/${id}`).then(setSignal, () => setSignal(undefined)), [call, id]);
  useEffect(() => (setSignal(undefined), load()), [load]);
  const close = () => (setDeciding(null), setReason(""), setError(undefined));

  const set = async (status: Status, why?: string) => {
    try {
      await call(`/api/v1/signals/${id}`, { method: "PATCH", body: JSON.stringify({ status, ...(why && { reason: why }) }) });
      close();
      onChanged();
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <Panel
      aria-label="Signal details"
      title={signal?.rule.title ?? "Signal"}
      description={signal ? `${signal.host} · ${plural(signal.count, "event")}` : undefined}
      actions={
        <IconButton label="Close details" size="sm" onClick={onClose}>
          <X />
        </IconButton>
      }
    >
      {!signal ? (
        <p className="text-sm text-fg-muted">Loading…</p>
      ) : (
        <div className="flex flex-col gap-3 text-sm">
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityBadge severity={signal.severity} />
            <StatusChip status={signal.status} />
          </div>
          <p className="m-0 text-xs text-fg-muted">
            First {ago(signal.firstSeen)}, last {ago(signal.lastSeen)}
            {signal.changedBy ? ` · ${signal.changedBy}` : ""}
          </p>
          {signal.reason && <p className="m-0">{signal.reason}</p>}
          <div className="flex flex-col gap-1">
            <span className="text-2xs font-medium tracking-wider text-fg-muted uppercase">First events</span>
            <ul className="siem-list flex flex-col gap-1.5">
              {signal.events.map((e) => (
                <EventLine key={e.id} e={e} />
              ))}
              {!signal.events.length && <li className="text-xs text-fg-muted">The events are older than the retention period.</li>}
            </ul>
          </div>
          {can("editor") && (
            <div className="flex flex-wrap gap-2 border-t border-line pt-3">
              {signal.status === "new" && (
                <Button size="sm" onClick={() => void set("investigating")}>
                  Investigate
                </Button>
              )}
              {(signal.status === "new" || signal.status === "investigating") && (
                <>
                  <Button size="sm" onClick={() => setDeciding("closed")}>
                    Close
                  </Button>
                  <Button size="sm" onClick={() => setDeciding("false-positive")}>
                    False positive
                  </Button>
                </>
              )}
              {(signal.status === "closed" || signal.status === "false-positive") && (
                <Button size="sm" onClick={() => void set("investigating")}>
                  Reopen
                </Button>
              )}
            </div>
          )}
          <Dialog
            open={deciding !== null}
            onOpenChange={(open) => !open && close()}
            title={deciding === "false-positive" ? "Mark as a false positive" : "Close the signal"}
            description="A closed signal does not collect new matches: the next one is a new signal. Say why, for the next person."
            onSubmit={(e: FormEvent) => (e.preventDefault(), void set(deciding!, reason))}
            footer={
              <>
                <Button type="button" onClick={close}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" disabled={deciding === "false-positive" && reason.trim().length < 3}>
                  Save
                </Button>
              </>
            }
          >
            <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint={deciding === "false-positive" ? "Required." : "Optional."} error={error} />
          </Dialog>
        </div>
      )}
    </Panel>
  );
}

type Tab = "open" | "closed" | "false-positive";

function SignalsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const [tab, setTab] = useState<Tab>("open");
  const [sev, setSev] = useState<string[]>([]);
  const [host, setHost] = useState("");
  const [rows, setRows] = useState<Signal[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Signal | null>(null);

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ status: tab, limit: "200" });
      if (sev.length) p.set("severity", sev.join(","));
      if (host.trim()) p.set("host", host.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ signals: Signal[]; nextCursor?: string }>(`/api/v1/signals?${p}`);
    },
    [call, tab, sev, host],
  );
  const load = useCallback(() => void query().then((r) => (setRows(r.signals), setMore(r.nextCursor)), () => setRows([])), [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.signals]), setMore(r.nextCursor)));

  const columns: Column<Signal>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (s) => <SeverityBadge severity={s.severity} /> },
    { id: "rule", header: "Rule", width: "32%", cell: (s) => <span className="siem-wrap text-sm font-medium">{s.rule.title}</span> },
    { id: "host", header: "Host", cell: (s) => <span className="font-mono text-xs">{s.host}</span> },
    { id: "count", header: "Events", align: "right", cell: (s) => s.count },
    { id: "status", header: "Status", cell: (s) => <StatusChip status={s.status} /> },
    { id: "last", header: "Last seen", sortValue: (s) => s.lastSeen, cell: (s) => <span className="text-xs whitespace-nowrap">{ago(s.lastSeen)}</span> },
  ];
  const s = summary;
  return (
    <>
      <PageHeader title="Signals" description={s ? `${plural(s.events, "event")} kept · last event ${ago(s.lastEventAt)} · ${plural(s.rules.enabled, "rule")} on` : undefined} />
      {s && (
        <KpiGrid minWidth={150}>
          {LEVELS.map((l) => (
            <KpiCard key={l} label={l.charAt(0).toUpperCase() + l.slice(1)} value={s.open[l]} footer={<SeverityBadge severity={l} />} />
          ))}
          <KpiCard label="Events, 24 hours" value={s.eventsLastDay} tone="info" />
          <KpiCard label="Rules with an error" value={s.rules.failing} tone={s.rules.failing ? "warning" : "success"} />
        </KpiGrid>
      )}
      <Tabs<Tab>
        label="Signal views"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Open" },
          { value: "closed", label: "Closed" },
          { value: "false-positive", label: "False positives" },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setHost(""))}>
        <FacetFilter label="Severity" selected={sev} onChange={setSev} options={LEVELS.map((l) => ({ value: l, label: l.charAt(0).toUpperCase() + l.slice(1), count: tab === "open" ? s?.open[l] : undefined }))} />
        <SearchInput label="Host" className="w-56" value={host} onChange={(e) => setHost(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? "Open" : tab === "closed" ? "Closed" : "False positives"}
          description="What the rules found, most severe first. One signal is one rule on one host within an hour."
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Signals"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(x) => x.id}
            onRowClick={(x) => setOpen(x)}
            activeRowId={open?.id}
            minWidth={820}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? "No open signals" : "Nothing here"}>
                {s && s.events === 0 ? (
                  <>
                    No events have arrived. See <a href="/setup">Setup</a>.
                  </>
                ) : s && s.rules.enabled === 0 ? (
                  <>
                    No rule is on. Add one under <a href="/rules">Rules</a>.
                  </>
                ) : (
                  "Nothing matches these filters."
                )}
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <SignalPanel
            id={open.id}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Rules

const EXAMPLE = `title: Failed SSH login
level: medium
detection:
  selection:
    source: sshd
    message|contains: 'Failed password'
  condition: selection
`;

function RulesPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Rule[]>();
  const [editing, setEditing] = useState<{ id?: string; source: string } | null>(null);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<RuleTest>();
  const [testing, setTesting] = useState(false);
  const load = useCallback(() => void call<{ rules: Rule[] }>("/api/v1/rules?limit=500").then((r) => setRows(r.rules), () => setRows([])), [call]);
  useEffect(load, [load]);
  const close = () => (setEditing(null), setError(undefined), setResult(undefined));

  const test = async () => {
    setTesting(true);
    try {
      setResult(await call<RuleTest>("/api/v1/rules/test", { method: "POST", body: JSON.stringify({ source: editing!.source }) }));
      setError(undefined);
    } catch (err) {
      setResult(undefined);
      setError((err as Error).message);
    } finally {
      setTesting(false);
    }
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      if (editing!.id) await call(`/api/v1/rules/${editing!.id}`, { method: "PATCH", body: JSON.stringify({ source: editing!.source }) });
      else await call("/api/v1/rules", { method: "POST", body: JSON.stringify({ source: editing!.source }) });
      close();
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const toggle = (r: Rule) => call(`/api/v1/rules/${r.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !r.enabled }) }).then(() => (load(), reload()), () => {});
  const remove = (r: Rule) => call(`/api/v1/rules/${r.id}`, { method: "DELETE" }).then(() => (load(), reload()), () => {});

  const columns: Column<Rule>[] = [
    { id: "sev", header: "Level", width: "104px", cell: (r) => <SeverityBadge severity={r.level} /> },
    {
      id: "title",
      header: "Rule",
      width: "34%",
      sortValue: (r) => r.title,
      cell: (r) => (
        <span className="flex min-w-0 flex-col">
          <span className="siem-wrap text-sm font-medium">{r.title}</span>
          {r.description && <span className="siem-clamp text-xs text-fg-muted">{r.description}</span>}
          {r.lastError && <span className="text-xs text-danger">{r.lastError}</span>}
        </span>
      ),
    },
    { id: "matches", header: "Matches", align: "right", cell: (r) => r.matches },
    { id: "last", header: "Last match", cell: (r) => <span className="text-xs whitespace-nowrap">{r.lastMatchAt ? ago(r.lastMatchAt) : "never"}</span> },
    {
      id: "on",
      header: "On",
      cell: (r) => <Switch checked={r.enabled} disabled={!can("admin")} onCheckedChange={() => void toggle(r)} label={`${r.title} is on`} />,
    },
    {
      id: "actions",
      header: <span className="sr-only">Actions</span>,
      label: "Actions",
      align: "right",
      cell: (r) =>
        can("admin") && (
          <span className="flex justify-end gap-1">
            <Button size="sm" onClick={() => setEditing({ id: r.id, source: r.source })}>
              Edit
            </Button>
            <IconButton label={`Delete ${r.title}`} size="sm" onClick={() => void remove(r)}>
              <Trash2 />
            </IconButton>
          </span>
        ),
    },
  ];
  return (
    <>
      <PageHeader
        title="Rules"
        description="Sigma rules, as YAML or JSON. Every event is run through every rule that is on. Aggregations and timeframes are not supported yet."
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setEditing({ source: EXAMPLE })}>
              Add rule
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable
          label="Rules"
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(r) => r.id}
          minWidth={820}
          empty={<EmptyState title="No rules yet">{can("admin") ? "Add a Sigma rule to turn events into signals." : "An admin adds the rules."}</EmptyState>}
        />
      </Panel>
      <Dialog
        open={editing !== null}
        onOpenChange={(open) => !open && close()}
        title={editing?.id ? "Edit rule" : "Add a rule"}
        description="Test it against the newest events before it goes live."
        onSubmit={save}
        footer={
          <>
            <Button type="button" icon={<FlaskConical />} onClick={() => void test()} disabled={testing || !editing?.source.trim()}>
              {testing ? "Testing…" : "Test against recent events"}
            </Button>
            <Button type="button" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={!editing?.source.trim()}>
              Save rule
            </Button>
          </>
        }
      >
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Sigma rule</span>
          <textarea
            className="min-h-64 w-full rounded-md border border-line bg-subtle p-2 font-mono text-xs"
            spellCheck={false}
            value={editing?.source ?? ""}
            onChange={(e) => setEditing((x) => (x ? { ...x, source: e.target.value } : x))}
          />
        </label>
        {error && <p className="m-0 text-xs text-danger">{error}</p>}
        {result && (
          <div className="flex flex-col gap-1 text-sm">
            <span>
              Would have matched {plural(result.matches, "event")} of the newest {result.evaluated}, on {plural(result.hosts, "host")}.
            </span>
            <ul className="siem-list flex flex-col gap-1.5">
              {result.events.map((e) => (
                <EventLine key={e.id} e={e} />
              ))}
            </ul>
          </div>
        )}
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- Events

function EventsPage({ call }: { call: Call }) {
  const [q, setQ] = useState("");
  const [host, setHost] = useState("");
  const [rows, setRows] = useState<Event[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Event | null>(null);
  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ limit: "200" });
      if (q.trim()) p.set("q", q.trim());
      if (host.trim()) p.set("host", host.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ events: Event[]; nextCursor?: string }>(`/api/v1/events?${p}`);
    },
    [call, q, host],
  );
  useEffect(() => void query().then((r) => (setRows(r.events), setMore(r.nextCursor)), () => setRows([])), [query]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.events]), setMore(r.nextCursor)));

  const columns: Column<Event>[] = [
    { id: "time", header: "Time", width: "180px", sortValue: (e) => e.time, cell: (e) => <span className="text-xs whitespace-nowrap">{new Date(e.time).toLocaleString()}</span> },
    { id: "host", header: "Host", cell: (e) => <span className="font-mono text-xs">{e.host ?? "–"}</span> },
    { id: "source", header: "Source", cell: (e) => e.source ?? "–" },
    { id: "message", header: "Message", width: "48%", cell: (e) => <span className="siem-clamp text-xs">{e.message ?? ""}</span> },
  ];
  return (
    <>
      <PageHeader title="Events" description="What arrived, newest first. Search finds text in the message and in every field." />
      <FilterBar onClear={() => (setQ(""), setHost(""))}>
        <SearchInput label="Search" className="w-72" value={q} onChange={(e) => setQ(e.target.value)} />
        <SearchInput label="Host" className="w-56" value={host} onChange={(e) => setHost(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Events"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(e) => String(e.id)}
            onRowClick={(e) => setOpen(e)}
            activeRowId={open ? String(open.id) : undefined}
            minWidth={760}
            pageSize={50}
            empty={
              <EmptyState title="No events">
                Nothing matches, or nothing has arrived. See <a href="/setup">Setup</a>.
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <Panel
            aria-label="Event details"
            title={`Event ${open.id}`}
            actions={
              <IconButton label="Close details" size="sm" onClick={() => setOpen(null)}>
                <X />
              </IconButton>
            }
          >
            <ul className="siem-list">
              <EventLine e={open} />
            </ul>
          </Panel>
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Send events, add Sigma rules, and work the signals they raise." />
      <Panel title="Send events" description="Use SIEM_INGEST_TOKEN, set where siem runs, or an API token with the editor role from API tokens. One event or an array of up to 1000; events are flat JSON.">
        <Code>{`curl -sf -X POST -H "Authorization: Bearer $SIEM_INGEST_TOKEN" -H 'content-type: application/json' \\
  -d '{"host":"web-1","source":"sshd","message":"Failed password for root from 10.0.0.9"}' \\
  ${origin}/api/v1/events`}</Code>
      </Panel>
      <Panel title="Add a rule" description="Rules are Sigma, as YAML or JSON. Test one against recent events before it goes live.">
        <Code>{EXAMPLE}</Code>
        <ul className="siem-list mt-2 flex flex-col gap-1 text-sm text-fg-muted">
          <li>Fields take contains, startswith, endswith, re and all; a list of values means any of them.</li>
          <li>Conditions use and, or, not, parentheses and 1 of, any of, all of over names, patterns and them.</li>
          <li>One rule on one host within an hour is one signal, with a count and the first events.</li>
          <li>Aggregations (| count()) and timeframes are refused with a message, not ignored.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first event arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Send events, then add rules." actions={<StatusBadge tone="info">Waiting for the first event</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this siem for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this siem, and with which role. Viewers see everything; editors also work signals and test rules; admins also add and change rules, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "siem" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "signals", label: "Signals", icon: Bell, count: summary ? Object.values(summary.open).reduce((a, b) => a + b, 0) : undefined },
    { id: "rules", label: "Rules", icon: ShieldCheck, count: summary?.rules.total },
    { id: "events", label: "Events", icon: ScrollText },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const active = route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="siem"
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "signals" && summary && summary.events === 0 ? (
        <WelcomePage />
      ) : route.page === "signals" ? (
        <SignalsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "rules" ? (
        <RulesPage call={call} reload={reload} />
      ) : route.page === "events" ? (
        <EventsPage call={call} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy SIEM">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
