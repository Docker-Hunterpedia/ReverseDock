# rdock-limits

Rate limits with bounded memory; concurrency gates with queues arrive in v0.4.

**v0.1:** `RateLimiter`, a sharded token bucket keyed by client IP, route or header value, with a hard cap on tracked keys (idle buckets are dropped first, then the least recently used). Request size limits are enforced by `rdock-proxy`. Design: [architecture §8 and §15](../../docs/05-architecture.md).
