import { useQuery } from "@tanstack/react-query";
import { Link, Outlet } from "@tanstack/react-router";
import {
  Activity, FileCode2, Gauge, KeyRound, LayoutDashboard, LogOut, Monitor, Moon, Network,
  Plug, Route, ScrollText, Server, Settings, ShieldCheck, Sun, Layers,
} from "lucide-react";
import type { ComponentType } from "react";
import { type Session, api } from "../lib/api";
import { type Status, ago } from "../lib/status";
import type { Theme } from "../lib/theme";
import { Logo, StatusPill } from "./ui";

type Icon = ComponentType<{ size?: number; "aria-hidden"?: boolean }>;

const NAV: { label: string; to?: string; icon: Icon }[][] = [
  [
    { label: "Overview", to: "/", icon: LayoutDashboard },
    { label: "Routes", icon: Route },
    { label: "Services", icon: Server },
    { label: "Middlewares", icon: Layers },
    { label: "Certificates", icon: ShieldCheck },
    { label: "Listeners", icon: Network },
    { label: "Providers", icon: Plug },
    { label: "Security", to: "/security", icon: KeyRound },
  ],
  [
    { label: "Logs", icon: ScrollText },
    { label: "Metrics", icon: Gauge },
    { label: "Config", icon: FileCode2 },
  ],
  [{ label: "Settings", icon: Settings }],
];

const THEMES: { value: Theme; label: string; icon: Icon }[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
  { value: "system", label: "System", icon: Monitor },
];

/** The top bar's apply state (docs/08-design-system.md §2). */
function ApplyState() {
  const status = useQuery({
    queryKey: ["status"],
    queryFn: () => api<Status>("/status"),
    refetchInterval: 5000,
  });
  const last = status.data?.last_reload;
  if (!status.data || !last) return <StatusPill tone="muted">Connecting…</StatusPill>;
  if (last.result !== "applied") {
    return <StatusPill tone="warn">Rejected ({last.diagnostics.length} diagnostics)</StatusPill>;
  }
  return (
    <span aria-live="polite">
      <StatusPill tone="ok">Applied · gen {last.generation} · {ago(last.at)}</StatusPill>
    </span>
  );
}

export function Shell({ session, theme, setTheme, onLogout }: {
  session: Session;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  onLogout: () => void;
}) {
  return (
    <div className="min-h-screen bg-canvas">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:m-2 focus:rounded-sm focus:bg-surface focus:p-2">
        Skip to content
      </a>
      <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b border-line bg-surface px-4">
        <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <Logo size={26} />
          <span className="hidden sm:inline">ReverseDock</span>
        </Link>
        <div className="ml-auto flex items-center gap-2">
          <ApplyState />
          <div role="radiogroup" aria-label="Theme" className="flex rounded-sm border border-line">
            {THEMES.map(({ value, label, icon: Icon }) => (
              <button
                key={value}
                type="button"
                role="radio"
                aria-checked={theme === value}
                title={label}
                onClick={() => setTheme(value)}
                className={`flex size-8 items-center justify-center ${theme === value ? "bg-accent-soft text-accent-text" : "text-fg-3 hover:text-fg"}`}
              >
                <Icon size={15} aria-hidden />
                <span className="sr-only">{label}</span>
              </button>
            ))}
          </div>
          <span className="hidden text-[13px] text-fg-2 md:inline">
            {session.name} · {session.role}
          </span>
          <button
            type="button"
            onClick={onLogout}
            title="Log out"
            className="flex size-8 items-center justify-center rounded-sm text-fg-2 hover:bg-surface-2 hover:text-fg"
          >
            <LogOut size={16} aria-hidden />
            <span className="sr-only">Log out</span>
          </button>
        </div>
      </header>
      <nav aria-label="Pages" className="flex gap-1 overflow-x-auto border-b border-line bg-surface px-3 py-2 md:hidden">
        {NAV.flat().filter((item) => item.to).map(({ label, to }) => (
          <Link
            key={label}
            to={to}
            activeOptions={{ exact: true }}
            className="rounded-sm px-3 py-1.5 text-[13px] whitespace-nowrap text-fg-2"
            activeProps={{ className: "bg-accent-soft font-medium !text-fg" }}
          >
            {label}
          </Link>
        ))}
      </nav>
      <div className="flex">
        <nav aria-label="Main" className="sticky top-14 hidden h-[calc(100vh-56px)] w-60 shrink-0 overflow-y-auto border-r border-line bg-surface p-3 md:block">
          {NAV.map((group, i) => (
            <ul key={i} className={i > 0 ? "mt-3 border-t border-line pt-3" : ""}>
              {group.map(({ label, to, icon: Icon }) => (
                <li key={label}>
                  {to ? (
                    <Link
                      to={to}
                      activeOptions={{ exact: true }}
                      className="flex h-9 items-center gap-2.5 rounded-sm px-2.5 text-fg-2 hover:bg-surface-2 hover:text-fg"
                      activeProps={{ className: "bg-accent-soft font-medium !text-fg" }}
                    >
                      <Icon size={16} aria-hidden />
                      {label}
                    </Link>
                  ) : (
                    <span
                      aria-disabled
                      title="Coming in the next v0.5 steps"
                      className="flex h-9 cursor-default items-center gap-2.5 rounded-sm px-2.5 text-fg-3"
                    >
                      <Icon size={16} aria-hidden />
                      {label}
                      <span className="ml-auto text-[11px] tracking-wide uppercase">soon</span>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          ))}
          <p className="mt-4 flex items-center gap-1.5 px-2.5 text-xs text-fg-3">
            <Activity size={12} aria-hidden /> Admin API on this machine
          </p>
        </nav>
        <main id="main" className="min-w-0 flex-1 px-4 py-6 md:px-6">
          <div className="mx-auto max-w-[1280px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
