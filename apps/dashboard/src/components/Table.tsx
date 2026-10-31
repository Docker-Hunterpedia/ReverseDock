import type { ReactNode } from "react";

export const TH = "px-3 py-2 text-left text-xs font-medium tracking-[0.04em] text-fg-3 uppercase whitespace-nowrap";
export const TD = "border-t border-line px-3 py-2";

/** A dense table inside a card (docs/08-design-system.md, DataTable). */
export function Table({ head, children, empty }: { head: ReactNode; children: ReactNode; empty?: ReactNode }) {
  return (
    <div className="-m-4 overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-surface-2">
          <tr>{head}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
      {empty && <p className="border-t border-line px-3 py-6 text-center text-fg-3">{empty}</p>}
    </div>
  );
}

export function Tile({ label, value, sub, tone }: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: "ok" | "warn" | "danger";
}) {
  const stripe = tone ? { ok: "border-l-ok", warn: "border-l-warn", danger: "border-l-danger" }[tone] : "";
  return (
    <div className={`rounded-md border border-line bg-surface p-4 ${tone ? `border-l-4 ${stripe}` : ""}`}>
      <div className="text-xs font-medium tracking-[0.04em] text-fg-3 uppercase">{label}</div>
      <div className="mt-1.5 text-[28px] leading-[34px] font-semibold tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-[13px] text-fg-2">{sub}</div>}
    </div>
  );
}
