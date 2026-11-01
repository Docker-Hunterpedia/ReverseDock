import { useQuery } from "@tanstack/react-query";
import { Link, Outlet } from "@tanstack/react-router";
import {
  FileCode2, Gauge, KeyRound, LayoutDashboard, LogOut, Monitor, Moon, Network, PanelLeftClose,
  PanelLeftOpen, Plug, Route, ScrollText, Server, Settings, ShieldCheck, Sun, Layers,
} from "lucide-react";
import { type ComponentType, useState } from "react";
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
    { label: "Logs", to: "/logs", icon: ScrollText },
    { label: "Metrics", to: "/traffic", icon: Gauge },
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

const SIDEBAR_KEY = "rdock.sidebar";

function storedCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === "collapsed";
  } catch {
    return false;
  }
}

function storeCollapsed(collapsed: boolean): void {
  try {
    if (collapsed) localStorage.setItem(SIDEBAR_KEY, "collapsed");
    else localStorage.removeItem(SIDEBAR_KEY);
  } catch {
    // Storage can be unavailable; the sidebar then opens expanded next time.
  }
}

/** Light, dark and system as a segmented control; one cycling button when the rail is narrow. */
function ThemeSwitch({ theme, setTheme, narrow }: { theme: Theme; setTheme: (t: Theme) => void; narrow: boolean }) {
  if (narrow) {
    const index = THEMES.findIndex((t) => t.value === theme);
    const { icon: Icon, label } = THEMES[index] ?? THEMES[2]!;
    const next = THEMES[(index + 1) % THEMES.length]!;
    return (
      <button
        type="button"
        onClick={() => setTheme(next.value)}
        title={`Theme: ${label}. Switch to ${next.label}`}
        className="flex size-9 items-center justify-center rounded-sm text-fg-2 hover:bg-surface-2 hover:text-fg"
      >
        <Icon size={16} aria-hidden />
        <span className="sr-only">Theme: {label}</span>
      </button>
    );
  }
  return (
    <div role="radiogroup" aria-label="Theme" className="flex w-full rounded-sm border border-line p-0.5">
      {THEMES.map(({ value, label, icon: Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={theme === value}
          onClick={() => setTheme(value)}
          className={`flex h-7 flex-1 items-center justify-center gap-1.5 rounded-[4px] text-xs ${theme === value ? "bg-accent-soft font-medium text-accent-text" : "text-fg-3 hover:text-fg"}`}
        >
          <Icon size={14} aria-hidden />
          {label}
        </button>
      ))}
    </div>
  );
}

function NavItems({ narrow }: { narrow: boolean }) {
  return (
    <>
      {NAV.map((group, i) => (
        <ul key={i} className={i > 0 ? "mt-3 border-t border-line pt-3" : ""}>
          {group.map(({ label, to, icon: Icon }) => {
            const inner = (
              <>
                <Icon size={18} aria-hidden />
                <span className={narrow ? "sr-only" : "truncate"}>{label}</span>
                {!to && !narrow && <span className="ml-auto text-[11px] tracking-wide uppercase">soon</span>}
              </>
            );
            const base = `flex h-9 items-center gap-3 rounded-sm ${narrow ? "justify-center" : "px-2.5"}`;
            return (
              <li key={label}>
                {to ? (
                  <Link
                    to={to}
                    title={narrow ? label : undefined}
                    activeOptions={{ exact: true }}
                    className={`${base} text-fg-2 hover:bg-surface-2 hover:text-fg`}
                    activeProps={{ className: "bg-accent-soft font-medium !text-fg" }}
                  >
                    {inner}
                  </Link>
                ) : (
                  <span
                    aria-disabled
                    title={narrow ? `${label} (soon)` : "Coming in the next v0.5 steps"}
                    className={`${base} cursor-default text-fg-3`}
                  >
                    {inner}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      ))}
    </>
  );
}

export function Shell({ session, theme, setTheme, onLogout }: {
  session: Session;
  theme: Theme;
  setTheme: (theme: Theme) => void;
  onLogout: () => void;
}) {
  const [collapsed, setCollapsed] = useState(storedCollapsed);
  const [peek, setPeek] = useState(false);
  const narrow = collapsed && !peek;
  const toggle = () => {
    setCollapsed(!collapsed);
    storeCollapsed(!collapsed);
    setPeek(false);
  };
  const ToggleIcon = collapsed ? PanelLeftOpen : PanelLeftClose;

  return (
    <div className="min-h-screen bg-canvas">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-30 focus:m-2 focus:rounded-sm focus:bg-surface focus:p-2">
        Skip to content
      </a>
      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-surface px-4">
        <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <Logo size={26} />
          <span className="hidden sm:inline">ReverseDock</span>
        </Link>
        <div className="ml-auto flex items-center gap-2">
          <ApplyState />
          {/* On phones the sidebar is hidden, so theme and logout stay here. */}
          <div className="flex items-center gap-1 md:hidden">
            <ThemeSwitch theme={theme} setTheme={setTheme} narrow />
            <button type="button" onClick={onLogout} title="Log out" className="flex size-9 items-center justify-center rounded-sm text-fg-2 hover:bg-surface-2">
              <LogOut size={16} aria-hidden />
              <span className="sr-only">Log out</span>
            </button>
          </div>
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
        {/* The rail keeps its width in the layout; the panel inside widens over the page on hover. */}
        <div className={`sticky top-14 hidden h-[calc(100vh-56px)] shrink-0 transition-[width] duration-200 md:block ${collapsed ? "w-16" : "w-60"}`}>
          <aside
            onMouseEnter={() => collapsed && setPeek(true)}
            onMouseLeave={() => setPeek(false)}
            onFocus={() => collapsed && setPeek(true)}
            onBlur={(e) => {
              if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setPeek(false);
            }}
            className={`absolute inset-y-0 left-0 z-10 flex flex-col border-r border-line bg-surface transition-[width,box-shadow] duration-200 ${narrow ? "w-16" : "w-60"} ${collapsed && peek ? "shadow-[var(--rd-shadow-overlay)]" : ""}`}
          >
            <nav aria-label="Main" className="flex-1 overflow-x-hidden overflow-y-auto p-3">
              <NavItems narrow={narrow} />
            </nav>
            <div className="flex flex-col gap-2 border-t border-line p-3">
              <ThemeSwitch theme={theme} setTheme={setTheme} narrow={narrow} />
              <div className={`flex items-center gap-2.5 ${narrow ? "flex-col" : ""}`}>
                <span
                  title={narrow ? `${session.name} · ${session.role}` : undefined}
                  className="flex size-8 shrink-0 items-center justify-center rounded-full bg-accent-soft text-[13px] font-semibold text-accent-text uppercase"
                >
                  {session.name.slice(0, 1)}
                </span>
                {!narrow && (
                  <span className="min-w-0 flex-1 leading-tight">
                    <span className="block truncate text-[13px] font-medium">{session.name}</span>
                    <span className="block text-xs text-fg-3 capitalize">{session.role}</span>
                  </span>
                )}
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
              <button
                type="button"
                onClick={toggle}
                aria-expanded={!collapsed}
                title={collapsed ? "Keep the sidebar open" : "Collapse the sidebar"}
                className={`flex h-8 items-center gap-2.5 rounded-sm text-[13px] text-fg-3 hover:bg-surface-2 hover:text-fg ${narrow ? "justify-center" : "px-2.5"}`}
              >
                <ToggleIcon size={16} aria-hidden />
                <span className={narrow ? "sr-only" : ""}>{collapsed ? "Keep open" : "Collapse"}</span>
              </button>
            </div>
          </aside>
        </div>
        <main id="main" className="min-w-0 flex-1 px-4 py-6 md:px-6">
          <div className="mx-auto max-w-[1280px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
