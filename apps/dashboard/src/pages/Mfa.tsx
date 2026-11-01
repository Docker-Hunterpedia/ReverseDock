import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { AuthLayout } from "../components/AuthLayout";
import { Alert, Button, Field } from "../components/ui";
import { type Session, api, describe } from "../lib/api";

/** The second login step: a code from the authenticator app, or a recovery code. */
export function Mfa({ onCancel }: { onCancel: () => void }) {
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const verify = useMutation({
    mutationFn: () => api<Session>("/auth/mfa", { method: "POST", body: { code: code.trim() } }),
    onSuccess: (session) => queryClient.setQueryData(["session"], session),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    verify.mutate();
  };
  return (
    <AuthLayout
      title="Two-step verification"
      intro={
        recovery
          ? "Enter one of your recovery codes. Each works once."
          : "Enter the 6-digit code from your authenticator app."
      }
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field
          key={recovery ? "recovery" : "totp"}
          label={recovery ? "Recovery code" : "Authentication code"}
          required
          autoFocus
          mono
          autoComplete="one-time-code"
          inputMode={recovery ? "text" : "numeric"}
          pattern={recovery ? undefined : "[0-9]{6}"}
          maxLength={recovery ? 11 : 6}
          placeholder={recovery ? "xxxxx-xxxxx" : "123456"}
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
        {verify.error && <Alert>{describe(verify.error)}</Alert>}
        <Button type="submit" variant="primary" disabled={verify.isPending}>
          {verify.isPending ? "Checking…" : "Verify"}
        </Button>
        <div className="flex justify-between text-[13px]">
          <button type="button" className="text-link hover:underline" onClick={() => { setRecovery(!recovery); setCode(""); }}>
            {recovery ? "Use the authenticator app" : "Use a recovery code"}
          </button>
          <button type="button" className="text-fg-2 hover:underline" onClick={onCancel}>
            Log out
          </button>
        </div>
      </form>
    </AuthLayout>
  );
}
