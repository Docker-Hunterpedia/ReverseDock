# rdock-limits

Limits with bounded memory: the middlewares' counters and the adaptive limit behind `admission`.

**v0.1:** `RateLimiter`, a sharded token bucket keyed by client IP, route or header value, with a hard cap on tracked keys (idle buckets are dropped first, then the least recently used). Request size limits are enforced by `rdock-proxy`. **v0.4 and later:** concurrency gates with queues (`concurrency`) and `bandwidth`. **v0.8:** calendar-window quotas persisted under the data directory (`quota`). **v0.9 (released in 0.9.0-alpha.1, [ADR-0031](../../docs/decisions/0031-v0-9-scale.md)):** `shared`, the leased shares behind `scope: cluster` (a request never waits on the store; the cluster admits at most `L + N × max(c, ⌈L / N⌉)` per key and window while the store answers), `abuse` (counters and a bounded ban list that never evicts), and `admission` (AIMD and gradient limits with priority classes). Design: [architecture §8 and §15](../../docs/05-architecture.md).
