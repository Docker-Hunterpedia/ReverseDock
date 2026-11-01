import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { AuthLayout } from "../components/AuthLayout";
import { QrCode } from "../components/QrCode";
import { Alert, Button, Field } from "../components/ui";
import { type Session, api, describe } from "../lib/api";

interface Secret {
  secret: string;
  uri: string;
}

type Confirmed = Session & { recovery_codes: string[] };

/** TOTP enrolment, required for admins before anything else (admin.mfa). */
export function Enrol({ onCancel }: { onCancel: () => void }) {
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const started = useRef(false);

  const start = useMutation({
    mutationFn: () => api<Secret>("/auth/totp", { method: "POST", body: {} }),
  });
  const confirm = useMutation({
    mutationFn: () => api<Confirmed>("/auth/totp/confirm", { method: "POST", body: { code: code.trim() } }),
  });

  useEffect(() => {
    // One secret per visit: a second request would replace the one on screen.
    if (!started.current) {
      started.current = true;
      start.mutate();
    }
  }, [start]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    confirm.mutate();
  };

  if (confirm.data) {
    const { recovery_codes: codes, ...session } = confirm.data;
    return <RecoveryCodes codes={codes} onDone={() => queryClient.setQueryData(["session"], session)} />;
  }

  return (
    <AuthLayout
      title="Set up two-step verification"
      intro="Admins protect their account with an authenticator app (1Password, Bitwarden, Google Authenticator, Authy…)."
    >
      {start.error && <Alert>{describe(start.error)}</Alert>}
      {start.data && (
        <form onSubmit={submit} className="flex flex-col gap-4">
          <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
            <QrCode text={start.data.uri} />
            <div className="text-[13px] text-fg-2">
              <p>1. Scan the code with your app.</p>
              <p className="mt-2">Or enter this key by hand:</p>
              <p className="mt-1 font-mono text-xs break-all text-fg select-all">
                {start.data.secret.match(/.{1,4}/g)?.join(" ")}
              </p>
            </div>
          </div>
          <Field
            label="2. Enter the 6-digit code it shows"
            required
            mono
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            autoComplete="one-time-code"
            placeholder="123456"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          {confirm.error && <Alert>{describe(confirm.error)}</Alert>}
          <Button type="submit" variant="primary" disabled={confirm.isPending}>
            {confirm.isPending ? "Checking…" : "Turn on two-step verification"}
          </Button>
          <button type="button" className="text-[13px] text-fg-2 hover:underline" onClick={onCancel}>
            Log out
          </button>
        </form>
      )}
    </AuthLayout>
  );
}

/** The codes in two columns with copy and download. */
export function CodeList({ codes }: { codes: string[] }) {
  const download = useMemo(() => {
    const text = `ReverseDock recovery codes\nEach code works once.\n\n${codes.join("\n")}\n`;
    return URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  }, [codes]);
  useEffect(() => () => URL.revokeObjectURL(download), [download]);
  return (
    <>
      <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-sm border border-line bg-surface-2 p-4 font-mono text-[13px]">
        {codes.map((c) => <li key={c}>{c}</li>)}
      </ol>
      <div className="mt-3 flex gap-2">
        <Button onClick={() => void navigator.clipboard?.writeText(codes.join("\n"))}>Copy</Button>
        <a
          href={download}
          download="reversedock-recovery-codes.txt"
          className="inline-flex h-9 items-center rounded-sm border border-line px-3.5 text-sm font-medium hover:bg-surface-2"
        >
          Download
        </a>
      </div>
    </>
  );
}

/** Shows the recovery codes once, until the user confirms saving them. */
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <AuthLayout
      title="Save your recovery codes"
      intro="If you lose your phone, each of these codes lets you log in once. They are shown only now."
    >
      <CodeList codes={codes} />
      <label className="mt-5 flex items-center gap-2 text-[13px] text-fg-2">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        I have stored these codes somewhere safe.
      </label>
      <Button variant="primary" className="mt-4 w-full" disabled={!saved} onClick={onDone}>
        Continue to the dashboard
      </Button>
    </AuthLayout>
  );
}
