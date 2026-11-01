// Harbor UI building blocks (docs/08-design-system.md §4), kept small until the shadcn/ui
// components on Base UI arrive with the pages that need menus, dialogs and tables.

import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { useId } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-accent-ink hover:bg-accent-hover border-transparent",
  secondary: "bg-surface text-fg border-line hover:bg-surface-2",
  ghost: "bg-transparent text-fg-2 border-transparent hover:bg-surface-2 hover:text-fg",
  danger: "bg-surface text-danger border-line hover:bg-danger hover:text-white",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      className={`inline-flex h-9 items-center justify-center gap-2 rounded-sm border px-3.5 text-sm font-medium transition-colors duration-[120ms] disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${className}`}
      {...props}
    />
  );
}

export function Field({
  label,
  hint,
  error,
  mono = false,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: ReactNode;
  error?: string;
  mono?: boolean;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] font-medium text-fg-2">
        {label}
      </label>
      <input
        id={id}
        aria-describedby={hint || error ? hintId : undefined}
        aria-invalid={error ? true : undefined}
        className={`h-9 rounded-sm border bg-surface px-3 text-sm text-fg placeholder:text-fg-3 ${error ? "border-danger" : "border-line"} ${mono ? "font-mono" : ""}`}
        {...props}
      />
      {(error || hint) && (
        <p id={hintId} className={`text-[13px] ${error ? "text-danger" : "text-fg-3"}`}>
          {error ?? hint}
        </p>
      )}
    </div>
  );
}

export function Card({ title, actions, children, className = "" }: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-md border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export type Tone = "ok" | "warn" | "danger" | "info" | "muted";

const TONES: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
  info: "text-info",
  muted: "text-fg-3",
};

/** Dot plus text, never colour alone (WCAG 1.4.1). */
export function StatusPill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface-2 px-2.5 py-0.5 text-xs font-medium text-fg">
      <span aria-hidden className={`size-2 rounded-full bg-current ${TONES[tone]}`} />
      {children}
    </span>
  );
}

export function Alert({ tone = "danger", children }: { tone?: "danger" | "warn" | "info"; children: ReactNode }) {
  const border = { danger: "border-danger", warn: "border-warn", info: "border-info" }[tone];
  return (
    <div role="alert" className={`rounded-sm border-l-4 ${border} bg-surface-2 px-3 py-2 text-[13px] text-fg`}>
      {children}
    </div>
  );
}

/** The Berth symbol (docs/assets/logo). */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="24 24 208 208" width={size} height={size} role="img" aria-label="ReverseDock">
      <path
        fill="#F58F0A"
        d="M72 24H184A48 48 0 0 1 232 72V88H134A6 6 0 0 0 128 94V162A6 6 0 0 0 134 168H232V184A48 48 0 0 1 184 232H72A48 48 0 0 1 24 184V72A48 48 0 0 1 72 24Z"
      />
      <path
        className="fill-[#1C1917] dark:fill-[#F58F0A]"
        d="M152 108H196A4 4 0 0 1 200 112V144A4 4 0 0 1 196 148H152A4 4 0 0 1 148 144V112A4 4 0 0 1 152 108Z"
      />
    </svg>
  );
}
