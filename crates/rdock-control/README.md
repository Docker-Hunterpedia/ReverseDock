# rdock-control

The control plane of a ReverseDock cluster (H-HA-01…03, ADR-0031), as a library the `rdock`
binary runs under `rdock control run` (so the control plane reuses the admin API's users,
tokens, audit log and dashboard without any other crate depending on `rdock-admin`):

- **Cluster CA** (ECDSA P-256 with rcgen on ring), created on first start in
  `$RDOCK_DATA_DIR/control/ca/`. It signs the control plane's server certificate and a
  short-lived client certificate for each data plane.
- **Join tokens** `rdk_join_…`: single use, with an expiry; only the SHA-256 of the secret is
  stored.
- **Registry** of enrolled instances: certificate, the revision each serves, the outcome of the
  last bundle (ACK or NACK with diagnostics), revocation.
- **Bundle history**: each publication gets the next revision, the SHA-256 of its canonical
  JSON and the cluster id, stored compressed with zstd. Rollback publishes an earlier document
  as a new revision.
- **Rollout**: a published revision goes to one canary first and to the rest after a soak
  time; a NACK or a silent canary halts it with the others on the stable revision; resume and
  abandon (`control/rollout.json`; the rules are in `rollout.rs` and tested without processes).
- **Store server**: the `ClusterStore` of `rdock-cluster`, served to enrolled members over
  mutual TLS, on a directory only this process writes, so fenced writes are checked atomically.
- **Cluster listener**: TLS (client certificate optional for enrolment only), HTTP/2 or
  HTTP/1.1, the calls of `rdock_cluster::protocol`.

The control plane is not in the request path: data planes keep serving their last bundle while
it is away.

Every member of the store reads every key in it (the ACME account key and each certificate's
private key); writes are limited per key class, and a revoked instance is shut out from then
on without anything it read being taken back (ADR-0031, "As implemented (review fixes)"). One
control plane is active at a time; a highly available one is planned. Implemented in v0.9 and
unreleased.
