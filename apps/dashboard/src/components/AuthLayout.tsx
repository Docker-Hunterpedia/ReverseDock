import type { ReactNode } from "react";
import { Logo } from "./ui";

/** The centred card used before a session is complete. */
export function AuthLayout({ title, intro, children }: {
  title: string;
  intro?: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas px-4 py-10">
      <div className="w-full max-w-[420px]">
        <div className="mb-6 flex items-center gap-2.5">
          <Logo size={32} />
          <span className="text-lg font-semibold tracking-tight">ReverseDock</span>
        </div>
        <section className="rounded-md border border-line bg-surface p-6">
          <h1 className="text-[22px] leading-7 font-semibold">{title}</h1>
          {intro && <div className="mt-1.5 text-fg-2">{intro}</div>}
          <div className="mt-5">{children}</div>
        </section>
      </div>
    </main>
  );
}
