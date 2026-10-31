import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useMemo } from "react";
import { Chart } from "../components/Chart";
import { useToast } from "../components/Toast";
import { TD, TH, Table, Tile } from "../components/Table";
import { Alert, Button, Card, StatusPill } from "../components/ui";
import { type Session, api, describe } from "../lib/api";
import { type Backends, type MetricsSummary, duration, errorShare, percent, rate } from "../lib/metrics";
import { type Status, ago } from "../lib/status";
import { useEventStream } from "../lib/stream";

interface Event {
  type: string;
  time?: string;
  result?: string;
  trigger?: string;
  generation?: number;
  service?: string;
  backend?: string;
  state?: string;
  reason?: string;
  actor?: string;
  action?: string;
  resource?: string;
}

function describeEvent(e: Event): string {
  switch (e.type) {
    case "reload":
      return `Configuration ${e.result} (gen ${e.generation}, ${e.trigger})`;
    case "backend":
      return `${e.service} → ${e.backend} is ${e.state}: ${e.reason}`;
    case "admin":
      return `${e.actor} ${e.action}${e.resource ? ` ${e.resource}` : ""}${e.result && e.result !== "ok" ? ` (${e.result})` : ""}`;
    default:
      return e.type;
  }
}

export function Overview({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const status = useQuery({ queryKey: ["status"], queryFn: () => api<Status>("/status"), refetchInterval: 5000 });
  const metrics = useQuery({
    queryKey: ["metrics", 900],
    queryFn: () => api<MetricsSummary>("/metrics/summary?window=900"),
    refetchInterval: 2000,
  });
  const backends = useQuery({ queryKey: ["backends"], queryFn: () => api<Backends[]>("/backends"), refetchInterval: 5000 });
  const events = useEventStream<Event>("/api/v1/events/stream", 12);
  const reload = useMutation({
    mutationFn: () => api<{ result?: string; generation?: number }>("/config/reload", { method: "POST", body: {} }),
    onSuccess: (report) => toast(`Configuration reloaded; generation ${report.generation ?? "?"} is live.`),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["status"] }),
  });

  const total = metrics.data?.total;
  const chart = useMemo(() => {
    const series = total?.series ?? [];
    return {
      times: series.map((p) => p.second),
      series: [
        { label: "2xx", color: "--rd-ok", values: series.map((p) => p.classes[1]) },
        { label: "3xx", color: "--rd-info", values: series.map((p) => p.classes[2]) },
        { label: "4xx", color: "--rd-warn", values: series.map((p) => p.classes[3]) },
        { label: "5xx", color: "--rd-danger", values: series.map((p) => p.classes[4]) },
      ],
    };
  }, [total]);

  if (status.error) return <Alert>{describe(status.error)}</Alert>;
  const s = status.data;
  const last = s?.last_reload;
  const members = (backends.data ?? []).flatMap((b) => b.backends);
  const healthy = members.filter((m) => m.state === "up" && !m.drained).length;
  const routes = Object.entries(metrics.data?.routes ?? {}).sort(([, a], [, b]) => b.rate - a.rate).slice(0, 8);
  const lastMinute = total?.series.slice(-60) ?? [];
  const perSecond = lastMinute.reduce((sum, p) => sum + p.requests, 0) / Math.max(lastMinute.length, 1);

  return (
    <>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[22px] leading-7 font-semibold">Overview</h1>
          {s && (
            <p className="mt-1 text-fg-2">
              ReverseDock {s.version} · started {ago(s.started_at)} ·{" "}
              {last ? `configuration ${last.result} ${ago(last.at)} (gen ${s.generation})` : "no reload yet"}
            </p>
          )}
        </div>
        {session.role !== "viewer" && (
          <Button variant="primary" onClick={() => reload.mutate()} disabled={reload.isPending}>
            <RefreshCw size={15} aria-hidden className={reload.isPending ? "animate-spin" : ""} />
            Reload configuration
          </Button>
        )}
      </div>
      {reload.error && <div className="mb-4"><Alert>{describe(reload.error)}</Alert></div>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Tile label="Requests / s" value={rate(perSecond)} sub={`${total?.requests ?? 0} in 15 min`} />
        <Tile
          label="Error rate"
          value={total ? percent(total.classes[3] + total.classes[4], total.requests) : "—"}
          sub={total ? `${total.classes[4]} server errors, ${total.classes[3]} client errors` : undefined}
          tone={total && errorShare(total) > 0.05 ? "danger" : total && total.classes[4] > 0 ? "warn" : undefined}
        />
        <Tile label="p95 latency" value={duration(total?.p95)} sub={`p50 ${duration(total?.p50)} · p99 ${duration(total?.p99)}`} />
        <Tile
          label="Backends healthy"
          value={`${healthy}/${members.length}`}
          tone={members.length === 0 ? undefined : healthy === members.length ? "ok" : healthy === 0 ? "danger" : "warn"}
          sub={s ? `${s.listeners.length} listeners · ${s.certificates.length} automatic certificates` : undefined}
        />
      </div>

      <Card title="Traffic, last 15 minutes" className="mt-6" actions={<span className="text-[13px] text-fg-3">requests per second by status class</span>}>
        {chart.times.length > 0 ? <Chart times={chart.times} series={chart.series} /> : <p className="text-fg-3">Loading…</p>}
      </Card>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]">
        <Card title="Top routes">
          <Table
            head={<><th className={TH}>Route</th><th className={`${TH} text-right`}>Req/s</th><th className={`${TH} text-right`}>Errors</th><th className={`${TH} text-right`}>p95</th></>}
            empty={routes.length === 0 ? "No traffic yet." : undefined}
          >
            {routes.map(([name, r]) => (
              <tr key={name} className="hover:bg-surface-2">
                <td className={`${TD} font-mono text-[13px]`}>{name}</td>
                <td className={`${TD} text-right tabular-nums`}>{rate(r.rate)}</td>
                <td className={`${TD} text-right tabular-nums`}>{percent(r.classes[3] + r.classes[4], r.requests)}</td>
                <td className={`${TD} text-right tabular-nums`}>{duration(r.p95)}</td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card
          title="Recent events"
          actions={
            <StatusPill tone={events.state === "live" ? "ok" : "warn"}>
              {events.state === "live" ? "live" : events.state}
            </StatusPill>
          }
        >
          {events.entries.length === 0 ? (
            <p className="text-fg-3">Reloads, backend health changes and admin actions appear here as they happen.</p>
          ) : (
            <ul className="flex flex-col gap-2 text-[13px]">
              {events.entries.map((e, i) => (
                <li key={i} className="flex gap-2">
                  <StatusPill tone={e.state === "down" || e.result === "rejected" || e.result === "denied" ? "danger" : e.type === "admin" ? "info" : "ok"}>
                    {e.type}
                  </StatusPill>
                  <span className="min-w-0 break-words">{describeEvent(e)}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
