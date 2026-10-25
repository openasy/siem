// Agents and Hosts: siem-agent instances, and the hosts of the install's hosts file they read over SSH (ADR 0040,
// 0031, 0052). The same screens as Logs', without container logs.
import {
  Badge,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  navigate,
  PageHeader,
  Panel,
  SelectField,
  StatusBadge,
  TextField,
  type Column,
  useAgo,
} from "@openasy/ui";
import { useAuth } from "@openasy/auth/react";
import { Check, Copy, KeyRound, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import type { Agent, AgentSetup, Host, HostsFile } from "./api.ts";
import type { Call } from "./App.tsx";
import { useT, type T } from "./i18n.ts";

// What to write in the hosts file (ADR 0052), shown where there is nothing yet.
const EXAMPLE = `hosts:
  - name: web-1
    address: 10.0.0.5
    agent: dc1`;

/** Loads a path now and every `everyMs`; `reload` loads it again at once. */
function useData<D>(call: Call, path: string | null, everyMs = 15_000) {
  const [data, setData] = useState<D>();
  const load = useCallback(() => {
    if (path) call<D>(path).then(setData, () => {});
  }, [call, path]);
  useEffect(() => {
    setData(undefined);
    load();
    if (!everyMs) return;
    const timer = setInterval(load, everyMs);
    return () => clearInterval(timer);
  }, [load, everyMs]);
  return { data, reload: load };
}

/** A file, a command or a token to copy. */
function CopyCode({ children, label }: { children: string; label: string }) {
  const t = useT();
  return (
    <div className="flex flex-col gap-1.5">
      <pre tabIndex={0} aria-label={label} className="siem-code">
        {children}
      </pre>
      <div>
        <Button size="xs" icon={<Copy />} onClick={() => void navigator.clipboard?.writeText(children)}>
          {t("code.copy")}
        </Button>
      </div>
    </div>
  );
}

const HOST_STATUS = (t: T): Record<string, { tone: "success" | "warning" | "danger" | "info" | "neutral"; label: string }> => ({
  ok: { tone: "success", label: t("hostStatus.reading") },
  new: { tone: "info", label: t("hostStatus.new") },
  pending: { tone: "info", label: t("hostStatus.waitingForTheFirstRead") },
  "host-key-pending": { tone: "warning", label: t("hostStatus.checkTheHostKey") },
  "host-key-changed": { tone: "danger", label: t("hostStatus.hostKeyChanged") },
  unreachable: { tone: "danger", label: t("hostStatus.unreachable") },
  "auth-failed": { tone: "danger", label: t("hostStatus.loginRefused") },
  timeout: { tone: "warning", label: t("hostStatus.timedOut") },
  error: { tone: "danger", label: t("hostStatus.failed") },
});

function HostStatus({ status }: { status: string }) {
  const t = useT();
  const s = HOST_STATUS(t)[status] ?? { tone: "neutral" as const, label: status };
  return <StatusBadge tone={s.tone}>{s.label}</StatusBadge>;
}

function KeyCheck({ call, host, onDone }: { call: Call; host: Host; onDone: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const key = host.pendingHostKeys[0];
  if (!key) return null;
  return (
    <Callout
      tone={host.status === "host-key-changed" ? "danger" : "warning"}
      title={host.status === "host-key-changed" ? t("keyCheck.presentsAnotherKey", { name: host.name }) : t("keyCheck.checkTheKeyOf", { name: host.name })}
    >
      <span className="flex flex-col gap-2">
        <span>{t("keyCheck.onTheHostThisMust")}</span>
        <CopyCode
          label={t("keyCheck.commandToRunOnThe")}
        >{`ssh-keygen -lf /etc/ssh/ssh_host_${key.type.includes("ed25519") ? "ed25519" : key.type.startsWith("ecdsa") ? "ecdsa" : "rsa"}_key.pub`}</CopyCode>
        <span className="siem-wrap font-mono text-xs">{key.fingerprint}</span>
        {host.fileHostKey && (
          <span>
            {t("keyCheck.theHostsFileTrusts")} <span className="siem-wrap font-mono text-xs">{host.fileHostKey}</span> {t("keyCheck.forThisHostAndThe")}
          </span>
        )}
        {can("admin") && !host.fileHostKey && (
          <span>
            <Button
              variant="primary"
              icon={<KeyRound />}
              onClick={() =>
                void call(`/api/v1/hosts/${host.id}/host-key/accept`, { method: "POST", body: JSON.stringify({ fingerprint: key.fingerprint }) }).then(onDone)
              }
            >
              {t("keyCheck.itMatchesAccept")}
            </Button>
          </span>
        )}
      </span>
    </Callout>
  );
}

export function HostsPage({ call }: { call: Call }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const { data, reload } = useData<{ hosts: Host[]; file: HostsFile | null }>(call, "/api/v1/hosts", 10_000);
  const agents = useData<{ agents: Agent[] }>(call, "/api/v1/agents", 0).data?.agents ?? [];
  const file = data?.file;
  const waiting = (data?.hosts ?? []).filter((h) => h.pendingHostKeys.length > 0);
  const cols: Column<Host>[] = [
    {
      id: "name",
      header: t("hostsPage.host"),
      cell: (h) => <a href={`/events?${new URLSearchParams({ host: h.name })}`}>{h.name}</a>,
      sortValue: (h) => h.name,
    },
    { id: "address", header: t("hostsPage.address"), width: "150px", mono: true, cell: (h) => `${h.address}${h.port === 22 ? "" : `:${h.port}`}` },
    {
      id: "status",
      header: t("hostsPage.status"),
      width: "190px",
      cell: (h) => (
        <span title={h.statusDetail ?? undefined} className="flex flex-col gap-0.5">
          <span>
            <HostStatus status={h.status} />
          </span>
          {h.unreadable.length > 0 && (
            <span className="text-xs text-warning-text">
              {t("hostsPage.notReadable")} {h.unreadable.join(", ")}
            </span>
          )}
        </span>
      ),
    },
    {
      id: "events",
      header: t("hostsPage.events"),
      width: "90px",
      align: "right",
      mono: true,
      cell: (h) => h.eventsIn.toLocaleString(),
      sortValue: (h) => h.eventsIn,
    },
    { id: "last", header: t("hostsPage.lastRead"), width: "110px", cell: (h) => (h.lastSuccessAt ? ago(h.lastSuccessAt) : "–") },
    { id: "agent", header: t("hostsPage.agent"), width: "120px", cell: (h) => h.agent.name },
    {
      id: "actions",
      header: <span className="sr-only">{t("hostsPage.actions")}</span>,
      width: "120px",
      cell: (h) =>
        can("editor") &&
        h.hostKeys.length > 0 && (
          <Button size="xs" variant="ghost" icon={<RefreshCw />} onClick={() => void call(`/api/v1/hosts/${h.id}/read`, { method: "POST" }).then(reload)}>
            {t("hostsPage.readNow")}
          </Button>
        ),
    },
  ];
  return (
    <>
      <PageHeader title={t("hostsPage.hosts")} description={t("hostsPage.description")} />
      {agents.length === 0 && data && (
        <EmptyState
          title={t("hostsPage.addAnAgentFirst")}
          action={
            <Button variant="primary" onClick={() => navigate("/agents")}>
              {t("hostsPage.addAnAgent")}
            </Button>
          }
        >
          {t("hostsPage.agentIsInstalledOnce")}
        </EmptyState>
      )}
      {file?.error && (
        <Callout tone="danger" title={t("hostsPage.theHostsFileIsNot")}>
          {t("hostsPage.theHostsFromItsLast", { error: file.error, path: file.path })}
        </Callout>
      )}
      {!!file?.warnings.length && (
        <Callout tone="warning" title={t("hostsPage.theHostsFileHasSomething")}>
          {file.warnings.join(" ")}
        </Callout>
      )}
      {waiting.map((h) => (
        <KeyCheck key={h.id} call={call} host={h} onDone={reload} />
      ))}
      {agents.length > 0 && data?.hosts.length === 0 && (
        <EmptyState title={t("hostsPage.noHostsYet")}>
          {file ? t("hostsPage.noHostsYetPrepareOne") : t("hostsPage.noHostsFile")}
          <div className="mt-3 text-left">
            <CopyCode label={t("hostsPage.linesForTheHostsFile")}>{EXAMPLE}</CopyCode>
          </div>
        </EmptyState>
      )}
      {agents.length > 0 && !!data?.hosts.length && (
        <Panel flush>
          <DataTable
            label={t("hostsPage.hosts")}
            columns={cols}
            rows={data.hosts}
            getRowId={(h) => h.id}
            pageSize={50}
            density="compact"
            empty={<EmptyState title={t("hostsPage.noHostsYet")} />}
          />
        </Panel>
      )}
    </>
  );
}

const AGENT_STATUS = (t: T): Record<string, { tone: "success" | "warning" | "danger" | "info"; label: string }> => ({
  online: { tone: "success", label: t("agentStatus.online") },
  offline: { tone: "danger", label: t("agentStatus.offline") },
  "waiting-to-enrol": { tone: "info", label: t("agentStatus.waitingToEnrol") },
  "version-mismatch": { tone: "danger", label: t("agentStatus.otherVersion") },
});

/** How to start siem-agent with its one-time token, next to siem or in another network. */
function EnrollCommand({ token, expiresAt, version, onDone }: { token: string; expiresAt: string; version?: string; onDone: () => void }) {
  const t = useT();
  return (
    <Dialog
      open
      onOpenChange={(open) => !open && onDone()}
      size="lg"
      icon={<Check aria-hidden className="size-4" />}
      iconTone="success"
      title={t("enrollCommand.startTheAgentWithThis")}
      description={t("enrollCommand.itWorksOnceUntilAnd", { value: new Date(expiresAt).toLocaleString() })}
      footer={
        <Button variant="primary" onClick={onDone}>
          {t("enrollCommand.done")}
        </Button>
      }
    >
      <span className="flex flex-col gap-2">
        <span>{t("enrollCommand.onAServerThatReaches")}</span>
        <CopyCode label={t("enrollCommand.startTheAgent")}>
          {`openssl rand -hex 32 > openasy-agent-kek
docker run -d --name siem-agent --restart unless-stopped --read-only --tmpfs /tmp \\
  --cap-drop ALL --security-opt no-new-privileges \\
  -v siem-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \\
  -e SIEM_URL=${window.location.origin} -e SIEM_ENROLL_TOKEN=${token} \\
  ghcr.io/openasy/siem-agent:${version ?? "<the version of siem>"}`}
        </CopyCode>
      </span>
      <Callout tone="warning" title={t("enrollCommand.closingThisDialogHidesThe")}>
        {t("enrollCommand.ifItIsLostEnrol")}
      </Callout>
    </Dialog>
  );
}

export function AgentsPage({ call }: { call: Call }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const { data, reload } = useData<{ agents: Agent[] }>(call, "/api/v1/agents", 10_000);
  // The agent must be the same version as siem (ADR 0019).
  const version = useData<{ version: string }>(call, "/api/v1/version", 0).data?.version;
  const [name, setName] = useState("");
  const [created, setCreated] = useState<{ enrollToken: string; enrollExpiresAt: string }>();
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string>();
  const close = () => (setAdding(false), setName(""), setError(undefined));
  const enrolled = (data?.agents ?? []).filter((a) => a.caFingerprint);
  const [setupFor, setSetupFor] = useState("");
  const chosen = setupFor || enrolled[0]?.id || "";
  const setup = useData<AgentSetup>(call, chosen ? `/api/v1/agents/${chosen}/setup` : null, 0).data;
  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await call<{ enrollToken: string; enrollExpiresAt: string }>("/api/v1/agents", { method: "POST", body: JSON.stringify({ name }) });
      close();
      setCreated(r);
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const cols: Column<Agent>[] = [
    { id: "name", header: t("agentsPage.agent"), cell: (a) => a.name, sortValue: (a) => a.name },
    {
      id: "status",
      header: t("agentsPage.status"),
      width: "150px",
      cell: (a) => (
        <span title={a.lastError ?? undefined}>
          <Badge tone={AGENT_STATUS(t)[a.status]?.tone ?? "neutral"}>{AGENT_STATUS(t)[a.status]?.label ?? a.status}</Badge>
        </span>
      ),
    },
    { id: "hosts", header: t("agentsPage.hosts"), width: "80px", align: "right", cell: (a) => a.hosts },
    { id: "version", header: t("agentsPage.version"), width: "90px", mono: true, cell: (a) => a.version ?? "–" },
    { id: "ca", header: t("agentsPage.caFingerprint"), cell: (a) => <span className="siem-wrap font-mono text-xs">{a.caFingerprint ?? "–"}</span> },
    { id: "seen", header: t("agentsPage.lastSeen"), width: "110px", cell: (a) => (a.lastSeenAt ? ago(a.lastSeenAt) : "–") },
    {
      id: "actions",
      header: <span className="sr-only">{t("agentsPage.actions")}</span>,
      width: "200px",
      cell: (a) =>
        can("admin") && (
          <span className="flex gap-1">
            <Button
              size="xs"
              variant="ghost"
              icon={<RefreshCw />}
              onClick={() =>
                window.confirm(t("agentsPage.enrolAgainItsSecretStops", { name: a.name })) &&
                void call<{ enrollToken: string; enrollExpiresAt: string }>(`/api/v1/agents/${a.id}/enroll-token`, { method: "POST" }).then(
                  (r) => (setCreated(r), reload()),
                )
              }
            >
              {t("agentsPage.enrolAgain")}
            </Button>
            {a.hosts === 0 && (
              <Button
                size="xs"
                variant="ghost"
                icon={<Trash2 />}
                onClick={() =>
                  window.confirm(t("agentsPage.removeAgent", { name: a.name })) && void call(`/api/v1/agents/${a.id}`, { method: "DELETE" }).then(reload)
                }
              >
                {t("agentsPage.remove")}
              </Button>
            )}
          </span>
        ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("agentsPage.agents")}
        description={t("agentsPage.description")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {t("agentsPage.addAgent")}
            </Button>
          )
        }
      />
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        size="sm"
        title={t("agentsPage.addAnAgent")}
        description={t("agentsPage.nameItAfterWhereIt")}
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              {t("agentsPage.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!name}>
              {t("agentsPage.addAgent")}
            </Button>
          </>
        }
      >
        <TextField label={t("agentsPage.name")} value={name} onChange={(e) => setName(e.target.value)} placeholder="dc-frankfurt" error={error} />
      </Dialog>
      {created && <EnrollCommand token={created.enrollToken} expiresAt={created.enrollExpiresAt} version={version} onDone={() => setCreated(undefined)} />}
      <Panel flush>
        <DataTable
          label={t("agentsPage.agents")}
          columns={cols}
          rows={data?.agents ?? []}
          loading={!data}
          getRowId={(a) => a.id}
          density="compact"
          empty={<EmptyState title={t("agentsPage.noAgentsYet")} />}
        />
      </Panel>
      {setup && (
        <Panel
          title={t("agentsPage.prepareAHost")}
          description={t("agentsPage.runAsRootOnEach", { name: setup.agent.name })}
          actions={
            enrolled.length > 1 && (
              <SelectField
                label={t("agentsPage.forHostsReadBy")}
                value={chosen}
                onChange={(e) => setSetupFor(e.target.value)}
                options={enrolled.map((a) => ({ value: a.id, label: a.name }))}
              />
            )
          }
        >
          <div className="flex flex-col gap-3">
            <CopyCode label={t("agentsPage.commandsToPrepareAHost")}>{setup.hostSetup}</CopyCode>
            <span className="text-sm text-fg-muted">{t("agentsPage.orWhereSshdConfigCannot")}</span>
            <CopyCode label={t("agentsPage.authorizedKeysLine")}>{`# ~openasy/.ssh/authorized_keys\n${setup.authorizedKey}`}</CopyCode>
            <span className="siem-wrap text-xs text-fg-muted">{t("agentsPage.caFingerprintIs", { caFingerprint: setup.caFingerprint })}</span>
          </div>
        </Panel>
      )}
    </>
  );
}
