import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { AuthLayout } from "../components/AuthLayout";
import { Alert, Button, Field } from "../components/ui";
import { type Session, api, describe } from "../lib/api";

/** First run: the bootstrap token from the data directory creates the first admin. */
export function Setup() {
  const queryClient = useQueryClient();
  const [token, setToken] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const mismatch = repeat !== "" && repeat !== password;

  const create = useMutation({
    mutationFn: async () => {
      await api("/setup", { method: "POST", bearer: token.trim(), body: { name, password } });
      return api<Session>("/auth/login", { method: "POST", body: { name, password } });
    },
    onSuccess: (session) => {
      queryClient.setQueryData(["setup"], { needed: false });
      queryClient.setQueryData(["session"], session);
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!mismatch) create.mutate();
  };

  return (
    <AuthLayout
      title="Set up ReverseDock"
      intro="Create the first admin account. You need the one-time setup token that rdock wrote when it started."
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field
          label="Setup token"
          mono
          required
          autoComplete="off"
          spellCheck={false}
          placeholder="rdk_boot_…"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          hint={
            <>
              Read it on the server:{" "}
              <code className="font-mono text-fg-2">sudo cat /var/lib/rdock/admin/bootstrap-token</code>{" "}
              (or <code className="font-mono">$RDOCK_DATA_DIR/admin/bootstrap-token</code>). It works once and for 24 hours.
            </>
          }
        />
        <Field
          label="User name"
          required
          autoComplete="username"
          value={name}
          onChange={(e) => setName(e.target.value)}
          hint="Letters, digits, dots, dashes and underscores."
        />
        <Field
          label="Password"
          type="password"
          required
          minLength={12}
          maxLength={128}
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="At least 12 characters. A long phrase is best; common passwords are refused."
        />
        <Field
          label="Repeat password"
          type="password"
          required
          autoComplete="new-password"
          value={repeat}
          onChange={(e) => setRepeat(e.target.value)}
          error={mismatch ? "The passwords differ." : undefined}
        />
        {create.error && <Alert>{describe(create.error)}</Alert>}
        <Button type="submit" variant="primary" disabled={create.isPending || mismatch}>
          {create.isPending ? "Creating…" : "Create admin account"}
        </Button>
      </form>
    </AuthLayout>
  );
}
