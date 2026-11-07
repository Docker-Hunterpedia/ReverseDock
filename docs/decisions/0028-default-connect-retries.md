# ADR-0028: A failed connection is retried on another backend by default

- Status: accepted
- Date: 2026-11-07

## Context
Until now a service without `retries` never retried: one request failed whenever its backend could not be reached. Rolling updates hit this. In the 3-node Swarm lab of v0.6 (#194), 300 req/s across the nodes during a `start-first` rolling update lost 85 of 36,001 requests (0.23 %) and a `stop-first` update 31 (0.08 %): every failure was a request sent to a task Swarm had just stopped, which ReverseDock learns about only at its next task poll (Swarm sends no task events, [ADR-0026](0026-swarm-l4-static.md)), and each waited the full connect timeout. The same lab with one connect retry lost no request in any phase; the slowest request took 1.04 s, the per-attempt connect budget of ADR-0026. The same happens with the Docker provider when a container stops, and with any backend that goes away between health checks.

A failed connection is safe to retry for every method, because nothing reached the backend ([ADR-0015](0015-status-code-retries.md)). NGINX retries it by default (`proxy_next_upstream error timeout`, [docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream), checked 2026-11-07), and HAProxy retries connections by default (`retries 3`, [manual](https://docs.haproxy.org/3.2/configuration.html#4.2-retries), checked 2026-11-07).

## Decision
- A service without `retries` behaves exactly as if it had `retries: {}`: the documented defaults apply, which retry only `connect` failures, up to `attempts: 2` more times, each on a backend not tried yet, within `budget_percent: 20` of the requests in flight. Status codes, resets and read timeouts are still retried only when configured.
- `retries: { attempts: 0 }` turns retries off; it is the documented opt-out and no longer produces a warning.
- Non-final attempts use the per-attempt connect budget (`timeouts.connect_attempt`, 1 s, ADR-0026), so a dead backend costs about a second before the next one is tried.

## Consequences
- Rolling updates, scale-downs and container stops no longer fail requests while the proxy catches up, for every provider and for file configurations.
- A request to a service whose backends are all unreachable now takes up to two attempt budgets plus one connect timeout (about 7 s with the defaults) before it fails, instead of one connect timeout. The retry budget keeps a failing pool from multiplying load.
- A connect that timed out is retried only on a backend not tried yet, for every configuration: waiting again on an address that did not answer cannot help. So a single-backend service whose backend is gone still fails after one connect timeout, as before. A refused connection fails in microseconds and may still be tried again, which helps a backend that is restarting.
