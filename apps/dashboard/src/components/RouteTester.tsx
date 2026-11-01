import { useMutation, useQuery } from "@tanstack/react-query";
import { FlaskConical } from "lucide-react";
import { type FormEvent, useState } from "react";
import { api, describe } from "../lib/api";
import { Drawer } from "./Drawer";
import { Alert, Button, StatusPill } from "./ui";

interface Explained {
  listener: string;
  request: { host: string; path: string; method: string; client_ip: string };
  routes: { name: string; priority: number; rule: string; result: "matched" | "shadowed" | "no match"; reason?: string }[];
  outcome: {
    result: "route" | "404" | "https redirect";
    reason?: string;
    route?: string;
    service?: string;
    middlewares?: string[];
    backends?: { address: string; considered: boolean; reason: string | null; backup: boolean; slow_start_weight: number | null }[];
  };
}

const input = "h-9 rounded-sm border border-line bg-surface px-3 text-sm text-fg placeholder:text-fg-3";

/** "Test a request": how a request would be routed, never sent (POST /api/v1/routes/explain). */
export function RouteTester() {
  const [open, setOpen] = useState(false);
  const listeners = useQuery({ queryKey: ["listeners"], queryFn: () => api<{ name: string }[]>("/listeners"), enabled: open });
  const [form, setForm] = useState({ listener: "", method: "GET", host: "", path: "/", headers: "", client_ip: "" });
  const explain = useMutation({
    mutationFn: () => {
      const headers = Object.fromEntries(
        form.headers.split("\n").map((l) => l.split(/:(.*)/s)).filter((p) => p.length > 1 && p[0]?.trim()).map((p) => [p[0]?.trim(), p[1]?.trim()]),
      );
      return api<Explained>("/routes/explain", {
        method: "POST",
        body: { listener: form.listener, method: form.method, host: form.host, path: form.path, headers, client_ip: form.client_ip || null },
      });
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    explain.mutate();
  };
  const r = explain.data;
  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <FlaskConical size={15} aria-hidden />
        Test a request
      </Button>
      {open && (
        <Drawer title="Test a request" onClose={() => setOpen(false)}>
          <form onSubmit={submit} className="flex flex-col gap-3">
            <p className="text-[13px] text-fg-2">Shows which route a request would take and why, against the running configuration. Nothing is sent.</p>
            <div className="flex gap-2">
              <select aria-label="Method" className={input} value={form.method} onChange={(e) => setForm({ ...form, method: e.target.value })}>
                {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => <option key={m}>{m}</option>)}
              </select>
              <input aria-label="Host" required placeholder="app.example.com" className={`${input} min-w-0 flex-1 font-mono`} value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} />
            </div>
            <input aria-label="Path" placeholder="/path?query" className={`${input} font-mono`} value={form.path} onChange={(e) => setForm({ ...form, path: e.target.value })} />
            <div className="flex gap-2">
              <select aria-label="Listener" className={`${input} flex-1`} value={form.listener} onChange={(e) => setForm({ ...form, listener: e.target.value })}>
                <option value="">first listener</option>
                {(listeners.data ?? []).map((l) => <option key={l.name}>{l.name}</option>)}
              </select>
              <input aria-label="Client IP" placeholder="client IP (optional)" className={`${input} flex-1 font-mono`} value={form.client_ip} onChange={(e) => setForm({ ...form, client_ip: e.target.value })} />
            </div>
            <textarea aria-label="Headers" placeholder={"Headers, one per line\nAuthorization: Bearer …"} className="min-h-16 rounded-sm border border-line bg-surface p-2.5 font-mono text-[13px] text-fg placeholder:text-fg-3" value={form.headers} onChange={(e) => setForm({ ...form, headers: e.target.value })} />
            <Button type="submit" variant="primary" disabled={explain.isPending}>{explain.isPending ? "Checking…" : "Explain"}</Button>
          </form>
          {explain.error && <div className="mt-4"><Alert>{describe(explain.error)}</Alert></div>}
          {r && (
            <div className="mt-5 flex flex-col gap-4">
              <Alert tone={r.outcome.result === "route" ? "ok" : "warn"}>
                {r.outcome.result === "route" ? (
                  <>Route <strong className="font-mono">{r.outcome.route}</strong> → service <strong className="font-mono">{r.outcome.service}</strong>{r.outcome.middlewares?.length ? <> through {r.outcome.middlewares.join(" → ")}</> : null}</>
                ) : (
                  <><strong>{r.outcome.result}</strong>: {r.outcome.reason}</>
                )}
              </Alert>
              <section>
                <h3 className="mb-2 text-xs font-medium tracking-[0.04em] text-fg-3 uppercase">Routes on {r.listener}, in order</h3>
                <ol className="flex flex-col gap-1.5 text-[13px]">
                  {r.routes.map((route) => (
                    <li key={route.name} className="flex flex-col gap-0.5 rounded-sm border border-line p-2">
                      <span className="flex items-center gap-2">
                        <StatusPill tone={route.result === "matched" ? "ok" : route.result === "shadowed" ? "warn" : "muted"}>{route.result}</StatusPill>
                        <span className="font-mono font-medium">{route.name}</span>
                        <span className="ml-auto text-fg-3">priority {route.priority}</span>
                      </span>
                      <span className="font-mono text-fg-3">{route.rule}</span>
                      {route.reason && <span className="text-fg-2">{route.reason}</span>}
                    </li>
                  ))}
                </ol>
              </section>
              {r.outcome.backends && (
                <section>
                  <h3 className="mb-2 text-xs font-medium tracking-[0.04em] text-fg-3 uppercase">Backends of {r.outcome.service}</h3>
                  <ul className="flex flex-col gap-1.5 text-[13px]">
                    {r.outcome.backends.map((b) => (
                      <li key={b.address} className="flex flex-wrap items-center gap-2">
                        <StatusPill tone={b.considered ? "ok" : "danger"}>{b.considered ? "considered" : "excluded"}</StatusPill>
                        <span className="font-mono">{b.address}</span>
                        {b.reason && <span className="text-fg-2">{b.reason}</span>}
                        {b.slow_start_weight != null && <span className="text-fg-3">slow start: weight {b.slow_start_weight}</span>}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          )}
        </Drawer>
      )}
    </>
  );
}
