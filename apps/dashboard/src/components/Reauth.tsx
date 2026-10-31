import { type FormEvent, type ReactNode, createContext, use, useRef, useState } from "react";
import { ApiError, api, describe } from "../lib/api";
import { Drawer } from "./Drawer";
import { Alert, Button, Field } from "./ui";

type Run = <T>(action: () => Promise<T>) => Promise<T>;

const ReauthContext = createContext<Run | null>(null);

function needsPassword(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.message.startsWith("confirm your password");
}

/**
 * Runs sensitive actions; when the server asks for a recent password check (ASVS 7.5.1), asks
 * for the password and code, confirms them and runs the action again.
 */
export function ReauthProvider({ children }: { children: ReactNode }) {
  const [asking, setAsking] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const waiting = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);

  const run: Run = async (action) => {
    try {
      return await action();
    } catch (error) {
      if (!needsPassword(error)) throw error;
      await new Promise<void>((resolve, reject) => {
        waiting.current = { resolve, reject };
        setProblem(null);
        setAsking(true);
      });
      return action();
    }
  };

  const confirm = async (event: FormEvent) => {
    event.preventDefault();
    try {
      await api("/auth/reauth", { method: "POST", body: { password, code: code.trim() || undefined } });
      setAsking(false);
      setPassword("");
      setCode("");
      waiting.current?.resolve();
    } catch (error) {
      setProblem(describe(error));
    }
  };
  const cancel = () => {
    setAsking(false);
    waiting.current?.reject(new Error("cancelled"));
  };

  return (
    <ReauthContext value={run}>
      {children}
      {asking && (
        <Drawer title="Confirm it is you" onClose={cancel}>
          <form onSubmit={(e) => void confirm(e)} className="flex flex-col gap-4">
            <p className="text-fg-2">This change needs your password again (and a code if you use an authenticator app).</p>
            <Field label="Password" type="password" required autoFocus autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <Field label="Authentication code" mono inputMode="numeric" maxLength={11} autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} hint="Leave empty if you have no authenticator app." />
            {problem && <Alert>{problem}</Alert>}
            <div className="flex gap-2">
              <Button type="submit" variant="primary">Confirm</Button>
              <Button onClick={cancel}>Cancel</Button>
            </div>
          </form>
        </Drawer>
      )}
    </ReauthContext>
  );
}

export function useReauth(): Run {
  const run = use(ReauthContext);
  if (!run) throw new Error("outside ReauthProvider");
  return run;
}
