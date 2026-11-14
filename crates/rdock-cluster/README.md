# rdock-cluster

The data-plane side of a ReverseDock cluster (H-HA-01…03, ADR-0031), as a library with no
dependency on the admin API:

- **`ClusterStore`**: a small key-value store with compare-and-swap, and leases with an expiry
  and a fencing token, shared by every member of a cluster. The certificate manager
  (`rdock-acme`) takes a lease per certificate name before it orders, re-checks the store after
  taking it, journals the order, and writes the result with compare-and-swap.
- **Backends**: `MemoryStore` (tests; one lock and one clock, fencing enforced); `DirStore`,
  either *exclusive* (one process owns the directory: a single instance's ACME storage, the
  control plane's store; fencing enforced) or *shared* (a directory several instances mount:
  best effort, see below); and the control plane's store reached over mutual TLS.
- **Cluster-scoped limits** (`limits`): the background task that claims parts of each key's
  budget for `rdock-limits`' shared budgets, from a `ClusterStore` (compare-and-swap) or a
  Redis-compatible server (`resp`, a small RESP2 client over tokio-rustls), counts members and
  notices when the store goes away and comes back. The request path never waits on it.

## The shared directory is best effort

A shared directory has no compare-and-swap and no common clock. Leases are lock files whose
expiry is written by the holder's clock and judged by the reader's: instances whose clocks
disagree by more than the margin between a renewal and the expiry can both believe they hold a
lease. A fenced write checks the lease file before it writes, which does not stop a writer
paused between the check and the write. Caddy's certmagic documents the same limits for its
file storage. Keep clocks synchronised; the control plane's store enforces fencing.

## Status

Implemented in v0.9 and released in 0.9.0-alpha.1 (ADR-0031). The cluster protocol is version 1;
0.9.0-alpha.1 is the first release that carries it. The Redis backend is tested against the testkit's RESP server only, not against a
real Redis or Valkey. One active control plane serves the store; a highly available one is
planned.
