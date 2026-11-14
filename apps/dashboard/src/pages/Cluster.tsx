// The control plane's instance view (F-UI-07, ADR-0031): every enrolled data plane with its
// state, the revision it serves and is given, its version, identity expiry and last error; and
// the rollout of the newest revision, which operators can resume or abandon. A data plane
// answers 404 to the cluster API and the page says so.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ClusterInstance, ClusterInstanceState, ClusterInstances, ClusterRollout } from "../api";
import { TD, TH, Table, Tile } from "../components/Table";
import { useToast } from "../components/Toast";
import { Alert, Button, Card, StatusPill, type Tone } from "../components/ui";
import { ApiError, type Session, api, describe } from "../lib/api";
import { ago } from "../lib/status";

const STATE_TONE: Record<ClusterInstanceState, Tone> = {
  synced: "ok",
  behind: "warn",
  error: "danger",
  offline: "muted",
  revoked: "muted",
};

const PHASE_TONE: Record<ClusterRollout["phase"], Tone> = {
  none: "muted",
  canary: "info",
  soaking: "info",
  complete: "ok",
  halted: "danger",
};

/** "2026-12-13 (in 30 d)". */
function expiry(iso: string): string {
  const days = Math.round((Date.parse(iso) - Date.now()) / 86_400_000);
  return `${iso.slice(0, 10)} (${days >= 0 ? `in ${days} d` : `${-days} d ago`})`;
}

function RolloutCard({ rollout, session }: { rollout: ClusterRollout; session: Session }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const act = useMutation({
    mutationFn: (action: "resume" | "abandon") => api<Record<string, unknown>>(`/cluster/rollout/${action}`, { method: "POST", body: {} }),
    onSuccess: (answer, action) =>
      toast(action === "resume"
        ? `Every instance is given revision ${rollout.revision} now.`
        : `Abandoned: revision ${String(answer.revision)} republishes revision ${String(answer.rollback_of)} to every instance.`),
    onError: (error) => toast(describe(error), "danger"),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["cluster-instances"] }),
  });
  const running = rollout.phase === "canary" || rollout.phase === "soaking" || rollout.phase === "halted";
  const operator = session.role !== "viewer";
  return (
    <Card
      title={`Rollout of revision ${rollout.revision}`}
      actions={operator && running ? (
        <div className="flex gap-2">
          <Button className="h-8" disabled={act.isPending} onClick={() => act.mutate("resume")}>
            {rollout.phase === "halted" ? "Resume" : "Promote now"}
          </Button>
          {rollout.stable > 0 && (
            <Button className="h-8" variant="danger" disabled={act.isPending} onClick={() => act.mutate("abandon")}>
              Abandon
            </Button>
          )}
        </div>
      ) : undefined}
    >
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill tone={PHASE_TONE[rollout.phase]}>{rollout.phase}</StatusPill>
        <span className="text-[13px] text-fg-2">
          mode {rollout.mode} · stable revision {rollout.stable || "—"}
          {rollout.canary && <> · canary <span className="font-mono">{rollout.canary}</span></>}
        </span>
      </div>
      {rollout.halt && (
        <div className="mt-3">
          <Alert>
            Halted {ago(rollout.halt.at)}: {rollout.halt.reason}. Instances not given revision {rollout.revision} stay on revision {rollout.stable}.
          </Alert>
        </div>
      )}
      {rollout.phase === "soaking" && rollout.soak_ends_at && (
        <p className="mt-3 text-[13px] text-fg-2">The canary took it; the other instances follow at {rollout.soak_ends_at.replace("T", " ").slice(0, 19)} UTC.</p>
      )}
      {rollout.phase === "canary" && !rollout.canary && (
        <p className="mt-3 text-[13px] text-fg-2">No instance is online to take the revision first; the first one to connect becomes the canary.</p>
      )}
      <p className="mt-3 text-[13px] text-fg-3">
        Settings: {rollout.settings.mode === "canary"
          ? `one canary${rollout.settings.canary ? ` (${rollout.settings.canary})` : ""}, soak ${rollout.settings.soak_seconds} s, canary timeout ${rollout.settings.canary_timeout_seconds} s`
          : "every instance at once"}. A refusal (NACK) halts a rollout; abandon republishes the stable revision.
      </p>
    </Card>
  );
}

function InstanceRow({ i }: { i: ClusterInstance }) {
  return (
    <tr className="hover:bg-surface-2">
      <td className={`${TD} font-mono text-[13px]`}>{i.name}</td>
      <td className={TD}><StatusPill tone={STATE_TONE[i.state]}>{i.state}</StatusPill></td>
      <td className={`${TD} tabular-nums`}>
        {i.serving}
        {i.target !== i.serving && <span className="text-fg-3"> → {i.target}</span>}
      </td>
      <td className={`${TD} font-mono text-[13px]`}>{i.version ?? "—"}</td>
      <td className={`${TD} tabular-nums`}>{i.last_seen ? ago(i.last_seen) : "never"}</td>
      <td className={`${TD} tabular-nums`}>{expiry(i.certificate_not_after)}</td>
      <td className={`${TD} text-[13px] text-fg-2`}>{i.last_error ?? "—"}</td>
    </tr>
  );
}

export function Cluster({ session }: { session: Session }) {
  const cluster = useQuery({
    queryKey: ["cluster-instances"],
    queryFn: () => api<ClusterInstances>("/cluster/instances"),
    refetchInterval: 5000,
    retry: false,
  });
  const notControl = cluster.error instanceof ApiError && cluster.error.status === 404;
  const data = cluster.data;
  const count = (state: ClusterInstanceState) => data?.instances.filter((i) => i.state === state).length ?? 0;
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Cluster</h1>
      <p className="mb-6 text-fg-2">Data planes enrolled with this control plane, the revision each serves, and how the newest revision is rolled out.</p>
      {notControl ? (
        <Card title="Not a control plane">
          <p className="text-fg-2">
            This rdock is a data plane. The instance view is served by the control plane (<code className="font-mono">rdock control run</code>); open its dashboard to see every instance.
          </p>
        </Card>
      ) : (
        <>
          {cluster.error && <div className="mb-4"><Alert>{describe(cluster.error)}</Alert></div>}
          {data && (
            <>
              <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                <Tile label="Instances" value={data.instances.length} sub={data.name ?? data.cluster_id} />
                <Tile label="Synced" value={count("synced")} sub={`revision ${data.latest}`} tone={count("synced") === data.instances.length && data.instances.length > 0 ? "ok" : undefined} />
                <Tile label="Behind" value={count("behind")} tone={count("behind") > 0 ? "warn" : undefined} />
                <Tile label="Errors · offline" value={`${count("error")} · ${count("offline")}`} tone={count("error") > 0 ? "danger" : undefined} />
              </div>
              <RolloutCard rollout={data.rollout} session={session} />
              <Card title="Instances" className="mt-6">
                <Table
                  head={<><th className={TH}>Name</th><th className={TH}>State</th><th className={TH}>Revision</th><th className={TH}>Version</th><th className={TH}>Last seen</th><th className={TH}>Identity expires</th><th className={TH}>Last error</th></>}
                  empty={data.instances.length === 0 ? "No data plane has enrolled yet. Create a join token with `rdock control token create`." : undefined}
                >
                  {data.instances.map((i) => <InstanceRow key={i.name} i={i} />)}
                </Table>
              </Card>
            </>
          )}
        </>
      )}
    </>
  );
}
