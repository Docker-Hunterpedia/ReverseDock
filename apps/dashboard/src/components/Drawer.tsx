import { X } from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";

/** A right-side drawer over the list (docs/08-design-system.md §2); Escape closes it. */
export function Drawer({ title, badge, onClose, children, footer }: {
  title: ReactNode;
  badge?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-30 flex justify-end bg-black/30" onClick={onClose}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        className="flex h-full w-full max-w-[640px] flex-col rounded-l-lg border-l border-line bg-surface shadow-[var(--rd-shadow-overlay)] outline-none"
      >
        <header className="flex items-center gap-3 border-b border-line px-5 py-4">
          <h2 className="min-w-0 truncate font-mono text-[15px] font-semibold">{title}</h2>
          {badge}
          <button type="button" onClick={onClose} className="ml-auto rounded-sm p-1 text-fg-3 hover:bg-surface-2 hover:text-fg" title="Close">
            <X size={18} aria-hidden />
            <span className="sr-only">Close</span>
          </button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-5">{children}</div>
        {footer && <footer className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</footer>}
      </div>
    </div>
  );
}

export function OwnerBadge({ owner }: { owner: string }) {
  return (
    <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[11px] text-fg-2" title={`Owned by the ${owner} provider`}>
      {owner}
    </span>
  );
}
