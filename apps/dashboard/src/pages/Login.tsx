import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { AuthLayout } from "../components/AuthLayout";
import { Alert, Button, Field } from "../components/ui";
import { type Session, api, describe } from "../lib/api";

export function Login({ expired = false }: { expired?: boolean }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const login = useMutation({
    mutationFn: () => api<Session>("/auth/login", { method: "POST", body: { name, password } }),
    onSuccess: (session) => queryClient.setQueryData(["session"], session),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    login.mutate();
  };
  return (
    <AuthLayout title="Log in">
      <form onSubmit={submit} className="flex flex-col gap-4">
        {expired && !login.error && <Alert tone="info">Your session ended. Log in again.</Alert>}
        <Field
          label="User name"
          required
          autoFocus
          autoComplete="username"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <Field
          label="Password"
          type="password"
          required
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {login.error && <Alert>{describe(login.error)}</Alert>}
        <Button type="submit" variant="primary" disabled={login.isPending}>
          {login.isPending ? "Checking…" : "Log in"}
        </Button>
      </form>
    </AuthLayout>
  );
}
