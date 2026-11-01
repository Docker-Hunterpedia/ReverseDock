// The shape of GET /api/v1/status (crates/rdock/src/engine.rs).

export interface Diagnostic {
  severity: "error" | "warning" | "info";
  path: string;
  message: string;
  hint?: string;
}

export interface Status {
  version: string;
  commit: string;
  started_at: string;
  ready: boolean;
  generation: number;
  config_file: string | null;
  origin: string;
  listeners: { name: string; address: string; routes: number; tls: unknown }[];
  providers: Record<string, { state?: string; error?: string; objects?: number }>;
  certificates: { name?: string; domains?: string[]; not_after?: string; state?: string }[];
  last_reload: {
    at: string;
    generation: number;
    origin: string;
    result: "applied" | "rejected" | string;
    trigger: string;
    diagnostics: Diagnostic[];
  } | null;
}

/** "12 s ago", "5 min ago", "3 h ago", "2 d ago". */
export function ago(iso: string, now = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}
