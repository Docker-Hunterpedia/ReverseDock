// GET /api/v1/metrics/summary (rdock-observability::live).

export interface Point {
  second: number;
  requests: number;
  /** 1xx … 5xx. */
  classes: [number, number, number, number, number];
  errors: number;
}

export interface Summary {
  window_seconds: number;
  requests: number;
  rate: number;
  classes: [number, number, number, number, number];
  errors: number;
  bytes_in: number;
  bytes_out: number;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  series: Point[];
}

export interface MetricsSummary {
  total: Summary;
  routes: Record<string, Summary>;
  services: Record<string, Summary>;
}

export interface Backends {
  service: string;
  backends: { address: string; state: "up" | "down" | "trial"; in_flight: number; drained: boolean; weight: number; reason: string | null }[];
}

/** "12 ms", "1.4 s", "—". */
export function duration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 1) return `${(seconds * 1000).toFixed(seconds < 0.01 ? 1 : 0)} ms`;
  return `${seconds.toFixed(1)} s`;
}

export function rate(value: number): string {
  return value >= 100 ? value.toFixed(0) : value.toFixed(value >= 10 ? 1 : 2);
}

export function percent(part: number, whole: number): string {
  if (whole === 0) return "0 %";
  const p = (100 * part) / whole;
  return `${p < 1 && p > 0 ? p.toFixed(2) : p.toFixed(1)} %`;
}

export function bytes(n: number): string {
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** 4xx and 5xx over all responses. */
export function errorShare(s: Summary): number {
  return s.requests === 0 ? 0 : (s.classes[3] + s.classes[4]) / s.requests;
}
