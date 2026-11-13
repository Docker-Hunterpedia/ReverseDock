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

## The shared directory is best effort

A shared directory has no compare-and-swap and no common clock. Leases are lock files whose
expiry is written by the holder's clock and judged by the reader's: instances whose clocks
disagree by more than the margin between a renewal and the expiry can both believe they hold a
lease. A fenced write checks the lease file before it writes, which does not stop a writer
paused between the check and the write. Caddy's certmagic documents the same limits for its
file storage. Keep clocks synchronised; the control plane's store enforces fencing.
