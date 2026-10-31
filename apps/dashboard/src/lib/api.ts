// The admin API client. Same origin only; the session cookie travels by itself and every
// unsafe request carries the session's CSRF token (ADR-0024). Replaced by the client
// generated from the OpenAPI document once that exists (#105).

export type Role = "viewer" | "operator" | "admin";
export type Stage = "mfa" | "enrol" | "full";

export interface Session {
  name: string;
  role: Role;
  stage: Stage;
  csrf_token: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

let csrfSource: () => string = () => "";

/** Where the current session's CSRF token is read from at each request. */
export function readCsrfFrom(source: () => string): void {
  csrfSource = source;
}

interface Options {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  /** A bearer token, used only for the bootstrap token at first run. */
  bearer?: string;
}

export async function api<T>(path: string, options: Options = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const csrf = method === "GET" ? "" : csrfSource();
  if (csrf) headers["X-CSRF-Token"] = csrf;
  if (options.bearer) headers.Authorization = `Bearer ${options.bearer}`;
  const response = await fetch(`/api/v1${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = { error: text.trim() || response.statusText };
  }
  if (!response.ok) {
    const message =
      (data as { error?: string } | undefined)?.error ?? response.statusText;
    const retry = Number(response.headers.get("retry-after"));
    throw new ApiError(response.status, message, retry > 0 ? retry : undefined);
  }
  return data as T;
}

/** A message for the user from any error. */
export function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 429 && error.retryAfter) {
      return `Too many attempts. Try again in ${error.retryAfter} s.`;
    }
    return error.message;
  }
  return "Cannot reach ReverseDock. Is it running?";
}
