import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Drawer } from "../components/Drawer";
import { useReauth } from "../components/Reauth";
import { TD, TH, Table } from "../components/Table";
import { Alert, Button, Card, Field, StatusPill } from "../components/ui";
import { type Role, type Session, api, describe } from "../lib/api";

interface User {
  name: string;
  role: Role;
  disabled: boolean;
  created_at: number;
  mfa: boolean;
}

interface Token {
  id: string;
  name: string;
  role: string;
  created_by: string;
  created_at: number;
  expires_at: number | null;
  allowed_from: string[];
  last_used_at: number | null;
  last_used_from: string | null;
}

const select = "h-9 rounded-sm border border-line bg-surface px-2.5 text-sm text-fg";

function day(unix: number | null): string {
  return unix == null ? "never" : new Date(unix * 1000).toISOString().slice(0, 10);
}

/** Admins: add users, change their role, turn them off, reset their second factor, remove them. */
export function Users({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const reauth = useReauth();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/users") });
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState({ name: "", role: "viewer" as Role, password: "" });
  const done = () => void queryClient.invalidateQueries({ queryKey: ["users"] });
  const change = useMutation({
    mutationFn: ({ name, body }: { name: string; body: object }) =>
      reauth(() => api(`/users/${encodeURIComponent(name)}`, { method: "PATCH", body })),
    onSettled: done,
  });
  const remove = useMutation({
    mutationFn: (name: string) => reauth(() => api(`/users/${encodeURIComponent(name)}`, { method: "DELETE" })),
    onSettled: done,
  });
  const add = useMutation({
    mutationFn: () => reauth(() => api("/users", { method: "POST", body: draft })),
    onSuccess: () => {
      setAdding(false);
      setDraft({ name: "", role: "viewer", password: "" });
      done();
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    add.mutate();
  };
  const error = users.error ?? change.error ?? remove.error;
  return (
    <Card title="Users" actions={<Button className="h-8" onClick={() => setAdding(true)}><Plus size={14} aria-hidden />Add user</Button>}>
      {error && <div className="mb-3"><Alert>{describe(error)}</Alert></div>}
      <Table head={<><th className={TH}>Name</th><th className={TH}>Role</th><th className={TH}>Two-step</th><th className={TH}>State</th><th className={TH}><span className="sr-only">Actions</span></th></>}>
        {(users.data ?? []).map((u) => (
          <tr key={u.name} className="hover:bg-surface-2">
            <td className={`${TD} font-medium`}>{u.name}{u.name === session.name && <span className="ml-2 text-xs text-fg-3">you</span>}</td>
            <td className={TD}>
              <select
                aria-label={`Role of ${u.name}`}
                className={`${select} h-8`}
                value={u.role}
                onChange={(e) => change.mutate({ name: u.name, body: { role: e.target.value } })}
              >
                <option value="viewer">viewer</option>
                <option value="operator">operator</option>
                <option value="admin">admin</option>
              </select>
            </td>
            <td className={TD}>{u.mfa ? <StatusPill tone="ok">on</StatusPill> : <StatusPill tone="muted">off</StatusPill>}</td>
            <td className={TD}>{u.disabled ? <StatusPill tone="warn">disabled</StatusPill> : <StatusPill tone="ok">active</StatusPill>}</td>
            <td className={`${TD} text-right whitespace-nowrap`}>
              <div className="flex justify-end gap-1.5">
                <Button className="h-8" onClick={() => change.mutate({ name: u.name, body: { disabled: !u.disabled } })}>{u.disabled ? "Enable" : "Disable"}</Button>
                {u.mfa && <Button className="h-8" onClick={() => change.mutate({ name: u.name, body: { reset_mfa: true } })}>Reset two-step</Button>}
                {u.name !== session.name && <Button variant="danger" className="h-8" onClick={() => remove.mutate(u.name)}>Remove</Button>}
              </div>
            </td>
          </tr>
        ))}
      </Table>
      <p className="mt-6 text-[13px] text-fg-3">Every change ends the user's sessions; at least one enabled admin always remains.</p>
      {adding && (
        <Drawer title="Add user" onClose={() => setAdding(false)}>
          <form onSubmit={submit} className="flex flex-col gap-4">
            <Field label="User name" required autoFocus value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            <label className="flex flex-col gap-1.5 text-[13px] font-medium text-fg-2">
              Role
              <select className={select} value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value as Role })}>
                <option value="viewer">viewer: reads everything except secrets, users and the audit log</option>
                <option value="operator">operator: also reloads, drains and edits API objects</option>
                <option value="admin">admin: also manages users, tokens and settings</option>
              </select>
            </label>
            <Field label="First password" type="password" required minLength={12} autoComplete="new-password" value={draft.password} onChange={(e) => setDraft({ ...draft, password: e.target.value })} hint="Give it to them safely; admins set up two-step verification at their first login." />
            {add.error && <Alert>{describe(add.error)}</Alert>}
            <Button type="submit" variant="primary" disabled={add.isPending}>Add user</Button>
          </form>
        </Drawer>
      )}
    </Card>
  );
}

/** Your API tokens (everyone's for admins): create one (shown once), revoke. */
export function Tokens({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const reauth = useReauth();
  const tokens = useQuery({ queryKey: ["tokens"], queryFn: () => api<Token[]>("/tokens") });
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState({ name: "", role: "viewer", days: "90", allow: "" });
  const create = useMutation({
    mutationFn: () =>
      reauth(() =>
        api<Token & { token: string }>("/tokens", {
          method: "POST",
          body: {
            name: draft.name,
            role: draft.role,
            expires_in_days: Number(draft.days),
            allowed_from: draft.allow.split(/[\s,]+/).filter(Boolean),
          },
        }),
      ),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["tokens"] }),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/tokens/${id}`, { method: "DELETE" }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["tokens"] }),
  });
  const roles = ["metrics", "viewer", "operator", "admin"].slice(0, { viewer: 2, operator: 3, admin: 4 }[session.role]);
  return (
    <Card title="API tokens" className="mt-6" actions={<Button className="h-8" onClick={() => { create.reset(); setCreating(true); }}><Plus size={14} aria-hidden />Create token</Button>}>
      {(tokens.error || revoke.error) && <div className="mb-3"><Alert>{describe(tokens.error ?? revoke.error)}</Alert></div>}
      <Table
        head={<><th className={TH}>Name</th><th className={TH}>ID</th><th className={TH}>Role</th><th className={TH}>By</th><th className={TH}>Expires</th><th className={TH}>Last used</th><th className={TH}><span className="sr-only">Actions</span></th></>}
        empty={tokens.data && tokens.data.length === 0 ? "No tokens. Scripts and Prometheus use tokens; people use their login." : undefined}
      >
        {(tokens.data ?? []).map((t) => (
          <tr key={t.id} className="hover:bg-surface-2">
            <td className={`${TD} font-medium`}>{t.name}</td>
            <td className={`${TD} font-mono text-[13px]`}>{t.id}</td>
            <td className={TD}>{t.role}</td>
            <td className={TD}>{t.created_by}</td>
            <td className={`${TD} tabular-nums`}>{day(t.expires_at)}</td>
            <td className={`${TD} tabular-nums`}>{t.last_used_at ? `${day(t.last_used_at)} from ${t.last_used_from ?? "socket"}` : "never"}</td>
            <td className={`${TD} text-right`}><Button variant="danger" className="h-8" onClick={() => revoke.mutate(t.id)}>Revoke</Button></td>
          </tr>
        ))}
      </Table>
      {creating && (
        <Drawer title="Create API token" onClose={() => setCreating(false)}>
          {create.data ? (
            <div className="flex flex-col gap-3">
              <Alert tone="warn">Copy it now: it is shown only once.</Alert>
              <code className="rounded-sm border border-line bg-surface-2 p-3 font-mono text-[13px] break-all select-all">{create.data.token}</code>
              <div className="flex gap-2">
                <Button onClick={() => void navigator.clipboard?.writeText(create.data.token)}>Copy</Button>
                <Button variant="primary" onClick={() => setCreating(false)}>Done</Button>
              </div>
            </div>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="flex flex-col gap-4">
              <Field label="Name" required autoFocus placeholder="prometheus, ci-deploy" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
              <label className="flex flex-col gap-1.5 text-[13px] font-medium text-fg-2">
                Role (at most yours)
                <select className={select} value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value })}>
                  {roles.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </label>
              <Field label="Expires in days" type="number" min={1} max={365} required value={draft.days} onChange={(e) => setDraft({ ...draft, days: e.target.value })} />
              <Field label="Only from (optional)" mono placeholder="10.0.0.0/8, 192.0.2.10/32" value={draft.allow} onChange={(e) => setDraft({ ...draft, allow: e.target.value })} hint="Networks the token works from; empty means anywhere." />
              {create.error && <Alert>{describe(create.error)}</Alert>}
              <Button type="submit" variant="primary" disabled={create.isPending}>Create token</Button>
            </form>
          )}
        </Drawer>
      )}
    </Card>
  );
}

interface Record {
  time: string;
  seq: number;
  actor: string;
  method: string;
  client: string | null;
  action: string;
  resource: string | null;
  result: "ok" | "denied" | "failed";
  reason: string | null;
}

/** The hash-chained audit log, newest first, 100 at a time. Admins only. */
export function AuditLog() {
  const [pages, setPages] = useState<number[]>([]);
  const before = pages.at(-1);
  const audit = useQuery({
    queryKey: ["audit", before ?? "latest"],
    queryFn: () => api<Record[]>(`/audit?limit=100${before ? `&before=${before}` : ""}`),
  });
  const rows = audit.data ?? [];
  return (
    <Card title="Audit log" className="mt-6" actions={<span className="text-[13px] text-fg-3">rdock audit verify checks the chain</span>}>
      {audit.error && <Alert>{describe(audit.error)}</Alert>}
      <Table head={<><th className={TH}>Time</th><th className={TH}>Actor</th><th className={TH}>Action</th><th className={TH}>Resource</th><th className={TH}>Result</th><th className={TH}>Client</th></>}>
        {rows.map((r) => (
          <tr key={r.seq} className="hover:bg-surface-2">
            <td className={`${TD} font-mono text-[12.5px] whitespace-nowrap`}>{r.time.replace("T", " ").slice(0, 19)}</td>
            <td className={`${TD} font-mono text-[13px]`}>{r.actor}</td>
            <td className={`${TD} font-mono text-[13px]`}>{r.action}</td>
            <td className={`${TD} font-mono text-[13px]`}>{r.resource ?? ""}</td>
            <td className={TD} title={r.reason ?? undefined}>
              <StatusPill tone={r.result === "ok" ? "ok" : r.result === "denied" ? "warn" : "danger"}>{r.result}</StatusPill>
            </td>
            <td className={`${TD} font-mono text-[12.5px]`}>{r.client ?? "socket"}</td>
          </tr>
        ))}
      </Table>
      <div className="mt-6 flex gap-2">
        {pages.length > 0 && <Button className="h-8" onClick={() => setPages(pages.slice(0, -1))}>Newer</Button>}
        {rows.length === 100 && <Button className="h-8" onClick={() => setPages([...pages, rows[rows.length - 1]?.seq ?? 0])}>Older</Button>}
      </div>
    </Card>
  );
}
