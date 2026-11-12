# rdock-cache

The HTTP cache of ReverseDock (F-WEB-03, [ADR-0030](../../docs/decisions/0030-v0-8-cache-extensibility-gateway.md)).
It is the only crate that uses `pingora::cache` types, apart from the hook glue in `rdock-proxy`.

- `policy`: RFC 9111 policy as pure, unit-tested functions: storability (§3, §3.5), freshness
  lifetime and age (§4.2), request directives (§5.2.1), the `304` header update (§3.2, §4.3.4),
  `Vary` (§4.1), invalidation after unsafe methods (§4.4), `Cache-Status` (RFC 9211), the
  length-framed key, the query rule and cache tags.
- `Store`: pingora-cache `Storage` implementations. The memory store keeps bodies as
  reference-counted chunks; the disk store keeps one file per object (`ab/cd/<hex>`: a
  checksummed header with pingora-cache's serialised `CacheMeta`, the URL and tags, then the
  body), written under a temporary name and renamed when complete. Both evict least recently
  used objects, keep a URL and tag index for purges, and cancel fills a purge overtakes.
- `Registry`: one store per name per process (pingora-cache needs `&'static` stores); reloads
  reuse them, and a changed or removed definition is reported as taking effect after a restart.
- `CoalescingLock`: pingora-cache's lock, where a failed fill releases the waiters.
- `RoutePolicy`: a route's compiled `cache` middleware.

The disk store does not `fsync`: after a power loss recent objects may be missing, and the
start-up walk drops anything damaged or incomplete. The file-header decoder has a property
test here and a fuzz target in `tests/fuzz`.
