import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { Alert, Button, Card, StatusPill } from "../components/ui";
import { type Session, api, describe } from "../lib/api";
import { type Status, ago } from "../lib/status";

function Tile({ label, value, sub, tone }: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: "ok" | "warn" | "danger";
}) {
  const stripe = tone ? { ok: "border-l-ok", warn: "border-l-warn", danger: "border-l-danger" }[tone] : "";
  return (
    <div className={`rounded-md border border-line bg-surface p-4 ${tone ? `border-l-4 ${stripe}` : ""}`}>
      <div className="text-xs font-medium tracking-[0.04em] text-fg-3 uppercase">{label}</div>
      <div className="mt-1.5 text-[28px] leading-[34px] font-semibold tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-[13px] text-fg-2">{sub}</div>}
    </div>
  );
}

const TH = "px-3 py-2 text-left text-xs font-medium tracking-[0.04em] text-fg-3 uppercase";
const TD = "border-t border-line px-3 py-2";

export function Overview({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const status = useQuery({
    queryKey: ["status"],
    queryFn: () => api<Status>("/status"),
    refetchInterval: 5000,
  });
  const reload = useMutation({
    mutationFn: () => api<{ result?: string }>("/config/reload", { method: "POST", body: {} }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["status"] }),
  });
  const canReload = session.role !== "viewer";

  if (status.error) return <Alert>{describe(status.error)}</Alert>;
  if (!status.data) return <p className="text-fg-3">Loading…</p>;
  const s = status.data;
  const last = s.last_reload;
  const providers = Object.entries(s.providers);
  const routes = s.listeners.reduce((sum, l) => sum + l.routes, 0);

  return (
    <>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[22px] leading-7 font-semibold">Overview</h1>
          <p className="mt-1 text-fg-2">
            ReverseDock {s.version}
            {s.commit !== "dev" && <span className="font-mono text-fg-3"> · {s.commit.slice(0, 7)}</span>}
            {" · "}started {ago(s.started_at)}
          </p>
        </div>
        {canReload && (
          <Button variant="primary" onClick={() => reload.mutate()} disabled={reload.isPending}>
            <RefreshCw size={15} aria-hidden className={reload.isPending ? "animate-spin" : ""} />
            Reload configuration
          </Button>
        )}
      </div>
      {reload.error && <div className="mb-4"><Alert>{describe(reload.error)}</Alert></div>}
      {reload.data && (
        <div className="mb-4">
          <Alert tone="info">Reload {reload.data.result ?? "done"}.</Alert>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Tile
          label="State"
          value={s.ready ? "Ready" : "Not ready"}
          tone={s.ready ? "ok" : "danger"}
          sub={s.ready ? "Listeners bound, configuration applied" : "Starting or shutting down"}
        />
        <Tile
          label="Configuration"
          value={`gen ${s.generation}`}
          tone={last && last.result !== "applied" ? "warn" : undefined}
          sub={last ? `${last.result} ${ago(last.at)} · ${last.trigger}` : "never reloaded"}
        />
        <Tile label="Listeners" value={s.listeners.length} sub={`${routes} routes attached`} />
        <Tile
          label="Certificates"
          value={s.certificates.length}
          sub={providers.length ? `${providers.length} providers` : "file provider only"}
        />
      </div>

      {last && last.diagnostics.length > 0 && (
        <Card title="Diagnostics of the last reload" className="mt-6">
          <ul className="flex flex-col gap-2">
            {last.diagnostics.map((d, i) => (
              <li key={i} className="flex gap-3 text-[13px]">
                <StatusPill tone={d.severity === "error" ? "danger" : d.severity === "warning" ? "warn" : "info"}>
                  {d.severity}
                </StatusPill>
                <span className="font-mono text-fg-2">{d.path}</span>
                <span>{d.message}{d.hint && <span className="text-fg-3"> · {d.hint}</span>}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Listeners" className="mt-6">
        <div className="-m-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-2">
              <tr><th className={TH}>Name</th><th className={TH}>Address</th><th className={TH}>TLS</th><th className={`${TH} text-right`}>Routes</th></tr>
            </thead>
            <tbody>
              {s.listeners.map((l) => (
                <tr key={l.name} className="hover:bg-surface-2">
                  <td className={`${TD} font-medium`}>{l.name}</td>
                  <td className={`${TD} font-mono text-[13px]`}>{l.address}</td>
                  <td className={TD}>{l.tls ? <StatusPill tone="ok">TLS</StatusPill> : <StatusPill tone="muted">plain</StatusPill>}</td>
                  <td className={`${TD} text-right tabular-nums`}>{l.routes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="mt-6 text-[13px] text-fg-3">
        Configuration from <span className="font-mono">{s.config_file ?? s.origin}</span>. Traffic charts, routes and
        services arrive with the next v0.5 steps.
      </p>
    </>
  );
}
