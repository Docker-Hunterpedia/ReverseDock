import { CheckCircle2, XCircle } from "lucide-react";
import { type ReactNode, createContext, use, useCallback, useState } from "react";

type Tone = "ok" | "danger";

interface Message {
  id: number;
  tone: Tone;
  text: ReactNode;
}

type Notify = (text: ReactNode, tone?: Tone) => void;

const ToastContext = createContext<Notify | null>(null);

/** Short confirmations at the bottom end of the page, 4 s each (docs/08-design-system.md §4). */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const notify = useCallback<Notify>((text, tone = "ok") => {
    const id = Date.now() + Math.random();
    setMessages((list) => [...list, { id, tone, text }]);
    setTimeout(() => setMessages((list) => list.filter((m) => m.id !== id)), 4000);
  }, []);
  return (
    <ToastContext value={notify}>
      {children}
      <div aria-live="polite" className="pointer-events-none fixed right-4 bottom-4 z-40 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2">
        {messages.map((m) => (
          <div
            key={m.id}
            role="status"
            className="pointer-events-auto flex items-start gap-2.5 rounded-md border border-line bg-surface px-4 py-3 text-sm shadow-[var(--rd-shadow-overlay)]"
          >
            {m.tone === "ok" ? (
              <CheckCircle2 size={18} aria-hidden className="mt-px shrink-0 text-ok" />
            ) : (
              <XCircle size={18} aria-hidden className="mt-px shrink-0 text-danger" />
            )}
            <span>{m.text}</span>
          </div>
        ))}
      </div>
    </ToastContext>
  );
}

export function useToast(): Notify {
  const notify = use(ToastContext);
  if (!notify) throw new Error("outside ToastProvider");
  return notify;
}
