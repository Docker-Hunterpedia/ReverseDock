import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Chart } from "../components/Chart";
import { TD, TH, Table } from "../components/Table";
import { Alert, Card } from "../components/ui";
import { api, describe } from "../lib/api";
import { type MetricsSummary, type Summary, bytes, duration, percent, rate } from "../lib/metrics";

const WINDOWS = [
  { seconds: 60, label: "1 min" },
  { seconds: 300, label: "5 min" },
  { seconds: 900, label: "15 min" },
];

function Rows({ items }: { items: [string, Summary][] }) {
  return (
    <>
      {items.map(([name, s]) => (
        <tr key={name} className="hover:bg-surface-2">
          <td className={`${TD} font-mono text-[13px]`}>{name}</td>
          <td className={`${TD} text-right tabular-nums`}>{rate(s.rate)}</td>
          <td className={`${TD} text-right tabular-nums`}>{s.requests}</td>
          <td className={`${TD} text-right tabular-nums`}>{percent(s.classes[4], s.requests)}</td>
          <td className={`${TD} text-right tabular-nums`}>{duration(s.p50)}</td>
          <td className={`${TD} text-right tabular-nums`}>{duration(s.p95)}</td>
          <td className={`${TD} text-right tabular-nums`}>{duration(s.p99)}</td>
          <td className={`${TD} text-right tabular-nums`}>{bytes(s.bytes_out)}</td>
        </tr>
      ))}
    </>
  );
}

const HEAD = (
  <>
    <th className={TH}>Name</th>
    <th className={`${TH} text-right`}>Req/s</th>
    <th className={`${TH} text-right`}>Requests</th>
    <th className={`${TH} text-right`}>5xx</th>
    <th className={`${TH} text-right`}>p50</th>
    <th className={`${TH} text-right`}>p95</th>
    <th className={`${TH} text-right`}>p99</th>
    <th className={`${TH} text-right`}>Sent</th>
  </>
);

/** Live charts and per-route and per-service numbers from the 15-minute ring buffers. */
export function Metrics() {
  const [window, setWindow] = useState(300);
  const metrics = useQuery({
    queryKey: ["metrics", window],
    queryFn: () => api<MetricsSummary>(`/metrics/summary?window=${window}`),
    refetchInterval: 2000,
  });
  const total = metrics.data?.total;
  const charts = useMemo(() => {
    const series = total?.series ?? [];
    const times = series.map((p) => p.second);
    return {
      times,
      requests: [{ label: "requests", color: "--rd-accent", values: series.map((p) => p.requests) }],
      errors: [
        { label: "4xx", color: "--rd-warn", values: series.map((p) => p.classes[3]) },
        { label: "5xx", color: "--rd-danger", values: series.map((p) => p.classes[4]) },
        { label: "no backend answer", color: "--rd-text-3", values: series.map((p) => p.errors) },
      ],
    };
  }, [total]);
  const sorted = (map: Record<string, Summary> | undefined) =>
    Object.entries(map ?? {}).sort(([, a], [, b]) => b.requests - a.requests);

  return (
    <>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[22px] leading-7 font-semibold">Metrics</h1>
          <p className="mt-1 text-fg-2">
            From the last 15 minutes kept in memory; percentiles are estimates within about 19 %. For history, use Prometheus.
          </p>
        </div>
        <div role="radiogroup" aria-label="Window" className="flex rounded-sm border border-line p-0.5">
          {WINDOWS.map((w) => (
            <button
              key={w.seconds}
              type="button"
              role="radio"
              aria-checked={window === w.seconds}
              onClick={() => setWindow(w.seconds)}
              className={`h-7 rounded-[4px] px-3 text-xs ${window === w.seconds ? "bg-accent-soft font-medium text-accent-text" : "text-fg-3 hover:text-fg"}`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>
      {metrics.error && <Alert>{describe(metrics.error)}</Alert>}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card title="Requests per second">{charts.times.length > 0 && <Chart times={charts.times} series={charts.requests} height={200} />}</Card>
        <Card title="Errors per second">{charts.times.length > 0 && <Chart times={charts.times} series={charts.errors} height={200} />}</Card>
      </div>
      <Card title="Routes" className="mt-6">
        <Table head={HEAD} empty={sorted(metrics.data?.routes).length === 0 ? "No traffic in this window." : undefined}>
          <Rows items={sorted(metrics.data?.routes)} />
        </Table>
      </Card>
      <Card title="Services" className="mt-6">
        <Table head={HEAD} empty={sorted(metrics.data?.services).length === 0 ? "No traffic in this window." : undefined}>
          <Rows items={sorted(metrics.data?.services)} />
        </Table>
      </Card>
    </>
  );
}
