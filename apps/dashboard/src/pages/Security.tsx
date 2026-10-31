import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { Alert, Button, Card, Field, StatusPill } from "../components/ui";
import { AuditLog, Tokens, Users } from "./Access";
import { CodeList } from "./Enrol";
import { type Session, api, describe } from "../lib/api";
import { ago } from "../lib/status";

interface Listed {
  id: string;
  user: string;
  created_at: number;
  idle_seconds: number;
  client: string | null;
  current: boolean;
}

const TH = "px-3 py-2 text-left text-xs font-medium tracking-[0.04em] text-fg-3 uppercase";
const TD = "border-t border-line px-3 py-2";

interface MfaState {
  enrolled: boolean;
  recovery_codes_left: number;
  required: boolean;
}

/** Two-step verification status and new recovery codes after confirming the password. */
function TwoStep() {
  const queryClient = useQueryClient();
  const state = useQuery({ queryKey: ["mfa"], queryFn: () => api<MfaState>("/auth/mfa") });
  const [asking, setAsking] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const regenerate = useMutation({
    mutationFn: async () => {
      await api("/auth/reauth", { method: "POST", body: { password, code: code.trim() } });
      return api<{ recovery_codes: string[] }>("/auth/recovery-codes", { method: "POST", body: {} });
    },
    onSuccess: () => {
      setAsking(false);
      setPassword("");
      setCode("");
      void queryClient.invalidateQueries({ queryKey: ["mfa"] });
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    regenerate.mutate();
  };
  const s = state.data;
  return (
    <Card title="Two-step verification" className="mb-6">
      {state.error && <Alert>{describe(state.error)}</Alert>}
      {s && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-3">
            {s.enrolled ? <StatusPill tone="ok">On</StatusPill> : <StatusPill tone="warn">Off</StatusPill>}
            {s.enrolled && (
              <span className={s.recovery_codes_left <= 3 ? "text-warn" : "text-fg-2"}>
                {s.recovery_codes_left} of 10 recovery codes left
              </span>
            )}
            {s.enrolled && !asking && !regenerate.data && (
              <Button className="ml-auto" onClick={() => setAsking(true)}>Generate new recovery codes</Button>
            )}
          </div>
          {asking && (
            <form onSubmit={submit} className="flex max-w-md flex-col gap-3 rounded-sm border border-line p-4">
              <p className="text-[13px] text-fg-2">
                Confirm it is you. Your current recovery codes stop working as soon as the new ones are made.
              </p>
              <Field label="Password" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <Field
                label="Authentication code"
                required
                mono
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              {regenerate.error && <Alert>{describe(regenerate.error)}</Alert>}
              <div className="flex gap-2">
                <Button type="submit" variant="primary" disabled={regenerate.isPending}>
                  {regenerate.isPending ? "Generating…" : "Generate"}
                </Button>
                <Button variant="ghost" onClick={() => setAsking(false)}>Cancel</Button>
              </div>
            </form>
          )}
          {regenerate.data && (
            <div className="max-w-md">
              <Alert tone="warn">Save these now: they are shown only once, and the old codes no longer work.</Alert>
              <div className="mt-3"><CodeList codes={regenerate.data.recovery_codes} /></div>
              <Button className="mt-3" onClick={() => regenerate.reset()}>Done</Button>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

/** Two-step verification, users, sessions, API tokens and the audit log. */
export function Security({ session }: { session: Session }) {
  const queryClient = useQueryClient();
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api<Listed[]>("/auth/sessions"),
    refetchInterval: 15000,
  });
  const end = useMutation({
    mutationFn: (id: string) => api(`/auth/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["sessions"] }),
  });
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Security</h1>
      <p className="mb-6 text-fg-2">
        Two-step verification, {session.role === "admin" ? "users, everyone's sessions, API tokens and the audit log" : "your sessions and API tokens"}.
      </p>
      <TwoStep />
      {session.role === "admin" && <Users session={session} />}
      <Card title="Sessions" className={session.role === "admin" ? "mt-6" : ""}>
        {sessions.error && <Alert>{describe(sessions.error)}</Alert>}
        {end.error && <Alert>{describe(end.error)}</Alert>}
        <div className="-m-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-surface-2">
              <tr>
                <th className={TH}>User</th><th className={TH}>Client</th><th className={TH}>Logged in</th>
                <th className={TH}>Last active</th><th className={TH}><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {sessions.data?.map((s) => (
                <tr key={s.id} className="hover:bg-surface-2">
                  <td className={`${TD} font-medium`}>
                    {s.user} {s.current && <StatusPill tone="ok">this browser</StatusPill>}
                  </td>
                  <td className={`${TD} font-mono text-[13px]`}>{s.client ?? "CLI socket"}</td>
                  <td className={TD}>{ago(new Date(s.created_at * 1000).toISOString())}</td>
                  <td className={TD}>{s.idle_seconds < 5 ? "now" : `${s.idle_seconds} s ago`}</td>
                  <td className={`${TD} text-right`}>
                    {!s.current && (
                      <Button variant="danger" className="h-8" disabled={end.isPending} onClick={() => end.mutate(s.id)}>
                        End
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Tokens session={session} />
      {session.role === "admin" && <AuditLog />}
    </>
  );
}
