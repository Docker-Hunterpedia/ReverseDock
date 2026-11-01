import { useEffect, useRef, useState } from "react";

export type StreamState = "connecting" | "live" | "paused" | "reconnecting";

/**
 * Keeps the last `max` entries of a server-sent events stream (EventSource sends the session
 * cookie and resumes with Last-Event-ID by itself). `lagged` and `reset` events are counted.
 */
export function useEventStream<T>(path: string | null, max: number, paused = false) {
  const [entries, setEntries] = useState<T[]>([]);
  const [state, setState] = useState<StreamState>("connecting");
  const [missed, setMissed] = useState(0);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  useEffect(() => {
    if (!path) return;
    setEntries([]);
    setState("connecting");
    const source = new EventSource(path);
    source.onopen = () => setState(pausedRef.current ? "paused" : "live");
    source.onerror = () => setState("reconnecting");
    source.onmessage = (event) => {
      if (pausedRef.current) return;
      try {
        const entry = JSON.parse(event.data as string) as T;
        setEntries((list) => [entry, ...list].slice(0, max));
      } catch {
        // A line that is not JSON is skipped.
      }
    };
    source.addEventListener("lagged", (event) => setMissed((n) => n + Number((event as MessageEvent).data)));
    source.addEventListener("reset", () => setEntries([]));
    return () => source.close();
  }, [path, max]);

  useEffect(() => {
    setState((s) => (paused ? "paused" : s === "paused" ? "live" : s));
  }, [paused]);

  return { entries, state, missed, clear: () => setEntries([]) };
}
