import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Card, StatusPill } from "../components/ui";
import { api } from "../lib/api";
import type { Status } from "../lib/status";
import type { Theme } from "../lib/theme";

interface Admin {
  listener: string;
  allowed_hosts: string[];
  tls: unknown;
  dashboard: boolean;
  mfa: string;
  api_writes: boolean;
  metrics_unauthenticated_on_loopback: boolean;
  sessions: { idle: string; absolute: string };
  passwords: { min_length: number; argon2: { memory_kib: number; iterations: number; parallelism: number } };
  tokens: { default_expiry_days: number; allow_no_expiry: boolean };
  audit: { retention: string; max_file_size: string; forward: { syslog: string } | null };
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 border-t border-line py-2.5 first:border-t-0 sm:grid-cols-[14rem_1fr]">
      <dt className="text-[13px] text-fg-3">{label}</dt>
      <dd className="min-w-0 text-sm break-words">{children}</dd>
    </div>
  );
}

const THEMES: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "Follow the system" },
];

/** The instance and its admin settings, read-only: they live in rdock.yaml (`admin:`). */
export function Settings({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  const status = useQuery({ queryKey: ["status"], queryFn: () => api<Status>("/status") });
  const config = useQuery({ queryKey: ["config"], queryFn: () => api<{ config: { admin: Admin } }>("/config") });
  const admin = config.data?.config.admin;
  const s = status.data;
  return (
    <>
      <h1 className="mb-1 text-[22px] leading-7 font-semibold">Settings</h1>
      <p className="mb-6 text-fg-2">
        Admin settings come from the <code className="font-mono">admin:</code> section of rdock.yaml; change them there and reload.
      </p>
      <Card title="Appearance">
        <div role="radiogroup" aria-label="Theme" className="flex flex-wrap gap-2">
          {THEMES.map((t) => (
            <button
              key={t.value}
              type="button"
              role="radio"
              aria-checked={theme === t.value}
              onClick={() => setTheme(t.value)}
              className={`h-9 rounded-sm border px-3.5 text-sm ${theme === t.value ? "border-accent bg-accent-soft font-medium" : "border-line hover:bg-surface-2"}`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </Card>
      <Card title="This instance" className="mt-6">
        <dl>
          <Row label="Version">{s ? `${s.version}${s.commit !== "dev" ? ` (${s.commit.slice(0, 12)})` : ""}` : "…"}</Row>
          <Row label="Configuration file"><span className="font-mono text-[13px] break-all">{s?.config_file ?? "zero-config"}</span></Row>
          <Row label="Started">{s?.started_at.replace("T", " ").slice(0, 19)} UTC</Row>
        </dl>
      </Card>
      {admin && (
        <Card title="Admin API" className="mt-6">
          <dl>
            <Row label="Listener"><span className="font-mono text-[13px]">{admin.listener}</span> {admin.tls ? <StatusPill tone="ok">TLS</StatusPill> : <StatusPill tone="muted">loopback, plain HTTP</StatusPill>}</Row>
            <Row label="Host names">{admin.allowed_hosts.length ? <span className="font-mono text-[13px]">{admin.allowed_hosts.join(", ")}</span> : "the listener's defaults"}</Row>
            <Row label="Configuration writes">{admin.api_writes ? "allowed through the API and this dashboard" : <StatusPill tone="info">off (GitOps)</StatusPill>}</Row>
            <Row label="Two-step verification">{{ required_for_admins: "required for admins", required: "required for everyone", optional: "optional" }[admin.mfa] ?? admin.mfa}</Row>
            <Row label="Sessions">end after {admin.sessions.idle} without activity, {admin.sessions.absolute} after login</Row>
            <Row label="Passwords">at least {admin.passwords.min_length} characters; Argon2id m={admin.passwords.argon2.memory_kib} KiB, t={admin.passwords.argon2.iterations}, p={admin.passwords.argon2.parallelism}</Row>
            <Row label="API tokens">expire after {admin.tokens.default_expiry_days} days by default{admin.tokens.allow_no_expiry ? "; tokens without expiry allowed" : ""}</Row>
            <Row label="Prometheus /metrics">{admin.metrics_unauthenticated_on_loopback ? "open on loopback" : "needs a token"}</Row>
            <Row label="Audit log">kept {admin.audit.retention}, files of {admin.audit.max_file_size}{admin.audit.forward ? `, forwarded to ${admin.audit.forward.syslog}` : ""}</Row>
          </dl>
        </Card>
      )}
    </>
  );
}
