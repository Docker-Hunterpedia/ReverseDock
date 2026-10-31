import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Card, StatusPill } from "../components/ui";
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

/** Sessions for now; users, tokens and the audit log follow (#111). */
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
        {session.role === "admin" ? "Everyone's sessions." : "Your sessions."} A session ends after 30 minutes
        without activity or 8 hours after login.
      </p>
      <Card title="Sessions">
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
    </>
  );
}
