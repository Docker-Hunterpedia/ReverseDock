import { Download, Pause, Play, Trash2 } from "lucide-react";
import { type FormEvent, Fragment, useMemo, useState } from "react";
import { Alert, Button, Card, StatusPill } from "../components/ui";
import { useEventStream } from "../lib/stream";

interface Line {
  ts: string;
  method: string;
  path: string;
  status: number;
  duration_ms: number;
  client_ip: string;
  host?: string;
  route?: string;
  service?: string;
  upstream?: string;
  tried?: string[];
  request_id: string;
  error?: string;
}

const KEEP = 1000;

function tone(status: number): "ok" | "info" | "warn" | "danger" {
  if (status >= 500 || status === 0) return "danger";
  if (status >= 400) return "warn";
  if (status >= 300) return "info";
  return "ok";
}

/** The live access log with server-side filters, pause, row details and download. */
export function Logs() {
  const [draft, setDraft] = useState({ route: "", service: "", status: "", client: "", q: "" });
  const [filter, setFilter] = useState(draft);
  const [paused, setPaused] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const path = useMemo(() => {
    const params = new URLSearchParams(Object.entries(filter).filter(([, v]) => v.trim() !== ""));
    const query = params.toString();
    return `/api/v1/logs/stream${query ? `?${query}` : ""}`;
  }, [filter]);
  const stream = useEventStream<Line>(path, KEEP, paused);

  const apply = (event: FormEvent) => {
    event.preventDefault();
    setFilter(draft);
  };
  const download = () => {
    const text = stream.entries.map((l) => JSON.stringify(l)).join("\n");
    const url = URL.createObjectURL(new Blob([`${text}\n`], { type: "application/x-ndjson" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "rdock-access-log.jsonl";
    link.click();
    URL.revokeObjectURL(url);
  };
  const input = "h-8 rounded-sm border border-line bg-surface px-2.5 text-[13px] text-fg placeholder:text-fg-3";

  return (
    <>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[22px] leading-7 font-semibold">Logs</h1>
          <p className="mt-1 text-fg-2">Requests as they happen, redacted like the access log. The last {KEEP} are kept here.</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusPill tone={stream.state === "live" ? "ok" : "warn"}>{stream.state}</StatusPill>
          <Button onClick={() => setPaused(!paused)} title={paused ? "Resume" : "Pause"}>
            {paused ? <Play size={15} aria-hidden /> : <Pause size={15} aria-hidden />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button onClick={stream.clear} title="Clear"><Trash2 size={15} aria-hidden />Clear</Button>
          <Button onClick={download} disabled={stream.entries.length === 0}><Download size={15} aria-hidden />Download</Button>
        </div>
      </div>
      <form onSubmit={apply} className="mb-4 flex flex-wrap gap-2">
        <input aria-label="Route" placeholder="route" className={`${input} font-mono`} value={draft.route} onChange={(e) => setDraft({ ...draft, route: e.target.value })} />
        <input aria-label="Service" placeholder="service" className={`${input} font-mono`} value={draft.service} onChange={(e) => setDraft({ ...draft, service: e.target.value })} />
        <input aria-label="Status" placeholder="status (404, 5xx)" className={`${input} w-36`} value={draft.status} onChange={(e) => setDraft({ ...draft, status: e.target.value })} />
        <input aria-label="Client address" placeholder="client IP prefix" className={`${input} font-mono`} value={draft.client} onChange={(e) => setDraft({ ...draft, client: e.target.value })} />
        <input aria-label="Text" placeholder="text" className={`${input} min-w-48 flex-1`} value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
        <Button type="submit" variant="primary" className="h-8">Filter</Button>
      </form>
      {stream.missed > 0 && (
        <div className="mb-4"><Alert tone="warn">{stream.missed} lines were skipped because the browser fell behind.</Alert></div>
      )}
      <Card>
        <div className="relative -m-4 overflow-x-auto" tabIndex={0} role="group" aria-label="Table, scrolls sideways">
          <table className="w-full font-mono text-[12.5px]">
            <tbody>
              {stream.entries.map((line) => (
                <Fragment key={line.request_id}>
                  <tr
                    tabIndex={0}
                    onClick={() => setOpen(open === line.request_id ? null : line.request_id)}
                    onKeyDown={(e) => e.key === "Enter" && setOpen(open === line.request_id ? null : line.request_id)}
                    className="cursor-pointer border-t border-line first:border-t-0 hover:bg-surface-2"
                  >
                    <td className="px-3 py-1.5 whitespace-nowrap text-fg-3">{line.ts.slice(11, 23)}</td>
                    <td className="px-2 py-1.5"><StatusPill tone={tone(line.status)}>{line.status}</StatusPill></td>
                    <td className="px-2 py-1.5 whitespace-nowrap">{line.method}</td>
                    <td className="max-w-[28rem] truncate px-2 py-1.5" title={line.path}>{line.host ? `${line.host}` : ""}{line.path}</td>
                    <td className="px-2 py-1.5 whitespace-nowrap text-fg-2" title="route → service → backend">
                      {line.route ?? "—"}
                      {line.service && <span className="text-fg-3"> → {line.service}</span>}
                      {line.upstream && <span className="text-fg-3"> → {line.upstream}</span>}
                      {line.tried && line.tried.length > 0 && <span className="text-warn"> (retried after {line.tried.join(", ")})</span>}
                    </td>
                    <td className="px-2 py-1.5 text-right whitespace-nowrap tabular-nums">{line.duration_ms.toFixed(1)} ms</td>
                    <td className="px-3 py-1.5 whitespace-nowrap text-fg-3">{line.client_ip}</td>
                  </tr>
                  {open === line.request_id && (
                    <tr className="bg-surface-2">
                      <td colSpan={7} className="px-3 py-2">
                        <pre className="overflow-x-auto text-[12px] whitespace-pre-wrap">{JSON.stringify(line, null, 2)}</pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {stream.entries.length === 0 && (
            <p className="px-3 py-8 text-center font-sans text-fg-3">
              {paused ? "Paused." : "Waiting for requests… Send one through a route to see it here."}
            </p>
          )}
        </div>
      </Card>
    </>
  );
}
