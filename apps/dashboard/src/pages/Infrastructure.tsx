import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { TD, TH, Table } from "../components/Table";
import { useToast } from "../components/Toast";
import { Alert, Button, Card, StatusPill } from "../components/ui";
import { type Session, api, describe } from "../lib/api";
import type { Backends } from "../lib/metrics";
import { Resources } from "./Resources";

/** Backends of every service, with drain and undrain for operators. */
function BackendsCard({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const backends = useQuery({ queryKey: ["backends"], queryFn: () => api<Backends[]>("/backends"), refetchInterval: 3000 });
  const drain = useMutation({
    mutationFn: ({ service, backend, drained }: { service: string; backend: string; drained: boolean }) =>
      api(`/backends/${drained ? "undrain" : "drain"}`, { method: "POST", body: { service, backend } }),
    onSuccess: (_, { service, backend, drained }) =>
      toast(drained ? `${backend} is back in rotation for ${service}.` : `${backend} drained: no new requests; open ones finish.`),
    onError: (error) => toast(describe(error), "danger"),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["backends"] }),
  });
  const rows = (backends.data ?? []).flatMap((s) => s.backends.map((b) => ({ service: s.service, ...b })));
  return (
    <Card title="Backends" className="mt-6">
      {drain.error && <div className="mb-3"><Alert>{describe(drain.error)}</Alert></div>}
      <Table
        head={<><th className={TH}>Service</th><th className={TH}>Address</th><th className={TH}>State</th><th className={`${TH} text-right`}>In flight</th><th className={TH}><span className="sr-only">Actions</span></th></>}
        empty={backends.data && rows.length === 0 ? "No backends in the running configuration." : undefined}
      >
        {rows.map((b) => (
          <tr key={`${b.service}/${b.address}`} className="hover:bg-surface-2">
            <td className={`${TD} font-mono text-[13px]`}>{b.service}</td>
            <td className={`${TD} font-mono text-[13px]`}>{b.address}</td>
            <td className={TD}>
              {b.drained ? <StatusPill tone="muted">drained</StatusPill> : <StatusPill tone={b.state === "up" ? "ok" : b.state === "trial" ? "warn" : "danger"}>{b.state}</StatusPill>}
            </td>
            <td className={`${TD} text-right tabular-nums`}>{b.in_flight}</td>
            <td className={`${TD} text-right`}>
              {session.role !== "viewer" && (
                <Button className="h-8" disabled={drain.isPending} onClick={() => drain.mutate({ service: b.service, backend: b.address, drained: b.drained })}>
                  {b.drained ? "Undrain" : "Drain"}
                </Button>
              )}
            </td>
          </tr>
        ))}
      </Table>
      <p className="mt-6 text-[13px] text-fg-3">Draining stops new requests to a backend; open ones finish. A restart forgets drains.</p>
    </Card>
  );
}

export function Services({ session }: { session: Session }) {
  return <Resources kind="services" session={session} extra={<BackendsCard session={session} />} />;
}

interface Automatic {
  names: string[];
  not_after: number | null;
  renew_at: number | null;
  renewal: string;
  failures: number;
  last_error: string | null;
}

function date(unix: number | null): string {
  if (unix == null) return "—";
  const d = new Date(unix * 1000);
  const days = Math.round((d.getTime() - Date.now()) / 86_400_000);
  return `${d.toISOString().slice(0, 10)} (${days >= 0 ? `in ${days} d` : `${-days} d ago`})`;
}

export function Certificates({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const certs = useQuery({
    queryKey: ["certificates"],
    queryFn: () => api<{ configured: Record<string, Record<string, unknown>> | null; automatic: Automatic[] }>("/certificates"),
    refetchInterval: 10000,
  });
  const renew = useMutation({
    mutationFn: (name: string) => api(`/certificates/${encodeURIComponent(name)}/renew`, { method: "POST", body: {} }),
    onSuccess: (_, name) => toast(`Renewal of ${name} requested; it runs within a few seconds.`),
    onError: (error) => toast(describe(error), "danger"),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["certificates"] }),
  });
  const automatic = certs.data?.automatic ?? [];
  const configured = Object.entries(certs.data?.configured ?? {});
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Certificates</h1>
      <p className="mb-6 text-fg-2">Automatic certificates renew by themselves; files you configured are reloaded when they change.</p>
      {(certs.error || renew.error) && <div className="mb-4"><Alert>{describe(certs.error ?? renew.error)}</Alert></div>}
      <Card title="Automatic (ACME and local CA)">
        <Table
          head={<><th className={TH}>Names</th><th className={TH}>Expires</th><th className={TH}>Renews</th><th className={TH}>State</th><th className={TH}><span className="sr-only">Actions</span></th></>}
          empty={certs.data && automatic.length === 0 ? "No automatic certificates. Routes on a TLS listener get one when acme is configured." : undefined}
        >
          {automatic.map((c) => (
            <tr key={c.names.join(",")} className="hover:bg-surface-2">
              <td className={`${TD} font-mono text-[13px]`}>{c.names.join(", ")}</td>
              <td className={`${TD} tabular-nums`}>{date(c.not_after)}</td>
              <td className={`${TD} tabular-nums`}>{date(c.renew_at)} <span className="text-fg-3">{c.renewal}</span></td>
              <td className={TD}>
                {c.last_error ? (
                  <span title={c.last_error}><StatusPill tone="danger">failed ×{c.failures}</StatusPill></span>
                ) : c.not_after ? (
                  <StatusPill tone="ok">valid</StatusPill>
                ) : (
                  <StatusPill tone="warn">pending</StatusPill>
                )}
              </td>
              <td className={`${TD} text-right`}>
                {session.role !== "viewer" && c.names[0] && (
                  <Button className="h-8" disabled={renew.isPending} onClick={() => renew.mutate(c.names[0] ?? "")}>Renew now</Button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="From files" className="mt-6">
        <Table head={<><th className={TH}>Name</th><th className={TH}>Certificate</th><th className={TH}>Key</th></>} empty={certs.data && configured.length === 0 ? "No certificate files configured." : undefined}>
          {configured.map(([name, c]) => (
            <tr key={name} className="hover:bg-surface-2">
              <td className={`${TD} font-mono text-[13px]`}>{name}</td>
              <td className={`${TD} font-mono text-[13px]`}>{String(c.cert_file ?? "—")}</td>
              <td className={`${TD} font-mono text-[13px]`}>{String(c.key_file ?? "—")}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}

interface Listener {
  name: string;
  address: string;
  routes: number;
  tls: unknown;
}

export function Listeners() {
  const listeners = useQuery({ queryKey: ["listeners"], queryFn: () => api<Listener[]>("/listeners") });
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Listeners</h1>
      <p className="mb-6 text-fg-2">The addresses rdock accepts connections on. Adding or removing one needs a restart (ADR-0008); everything else reloads.</p>
      {listeners.error && <Alert>{describe(listeners.error)}</Alert>}
      <Card>
        <Table head={<><th className={TH}>Name</th><th className={TH}>Address</th><th className={TH}>TLS</th><th className={`${TH} text-right`}>Routes</th></>}>
          {(listeners.data ?? []).map((l) => (
            <tr key={l.name} className="hover:bg-surface-2">
              <td className={`${TD} font-medium`}>{l.name}</td>
              <td className={`${TD} font-mono text-[13px]`}>{l.address}</td>
              <td className={TD}>{l.tls ? <StatusPill tone="ok">TLS</StatusPill> : <StatusPill tone="muted">plain</StatusPill>}</td>
              <td className={`${TD} text-right tabular-nums`}>{l.routes}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}

interface ProviderState {
  providers: Record<string, { state?: string; error?: string; objects?: number; last_sync?: string }>;
  diagnostics: { severity: string; path: string; message: string; hint?: string }[];
}

export function Providers() {
  const state = useQuery({ queryKey: ["providers"], queryFn: () => api<ProviderState>("/providers"), refetchInterval: 10000 });
  const providers = Object.entries(state.data?.providers ?? {});
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Providers</h1>
      <p className="mb-6 text-fg-2">Where routes and services come from besides the configuration file.</p>
      {state.error && <Alert>{describe(state.error)}</Alert>}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="file">
          <StatusPill tone="ok">active</StatusPill>
          <p className="mt-2 text-[13px] text-fg-2">The configuration file and its includes; reloaded when they change.</p>
        </Card>
        <Card title="api">
          <StatusPill tone="ok">active</StatusPill>
          <p className="mt-2 text-[13px] text-fg-2">Objects created in this dashboard or through the configuration API, named <code className="font-mono">name@api</code>.</p>
        </Card>
        {providers.map(([name, p]) => (
          <Card key={name} title={name}>
            <StatusPill tone={p.error ? "danger" : "ok"}>{p.error ? "unreachable" : (p.state ?? "active")}</StatusPill>
            {p.error && <p className="mt-2 text-[13px] text-danger">{p.error}</p>}
            {p.objects != null && <p className="mt-2 text-[13px] text-fg-2">{p.objects} objects</p>}
          </Card>
        ))}
      </div>
      <Card title="Diagnostics about provider objects" className="mt-6">
        {(state.data?.diagnostics ?? []).length === 0 ? (
          <p className="text-fg-3">Nothing to report.</p>
        ) : (
          <ul className="flex flex-col gap-2 text-[13px]">
            {state.data?.diagnostics.map((d, i) => (
              <li key={i} className="flex flex-wrap gap-2">
                <StatusPill tone={d.severity === "error" ? "danger" : "warn"}>{d.severity}</StatusPill>
                <span className="font-mono text-fg-2">{d.path}</span>
                <span>{d.message}{d.hint && <span className="text-fg-3"> · {d.hint}</span>}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
