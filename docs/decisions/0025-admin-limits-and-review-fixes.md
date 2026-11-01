# ADR-0025: Admin limits and changes from the v0.5 security review

- Status: accepted
- Date: 2026-11-01

## Context

[ADR-0024](0024-management-api-and-dashboard.md) put the admin API on its own runtime, so that it can never take worker threads from the proxy. The isolation test (`benchmarks/isolation/`, H-ENG-04) showed that this is not enough. In a container limited to 2 CPUs, one script making about 500 admin requests a second raised the proxy's p99 from 0.65 to 92 ms, and 10,000 silent connections raised it to 54 ms. Both runtimes share the container's CPU quota: when the admin side uses too much, the kernel pauses the whole process. Engine calls also run on the proxy's runtime.

The [ASVS 5.0 Level 2 review](../security/asvs-5.0-l2-admin.md) of the same surface found further gaps. v0.5 is not released, so these can be fixed before anyone depends on the earlier behaviour. This ADR records the changes that alter the public API, the configuration model or the security model.

## Decision

**Limits on the admin side.**
- At most 256 open TCP connections; more are closed as they arrive. Headers and TLS handshakes have 10 seconds.
- 20 requests a second per caller (each token, each user across their sessions, the CLI socket), bursts of 100, then `429` with `Retry-After`.
- 5 configuration writes or dry runs a second across all callers, bursts of 10, then `429`. Each one compiles a whole configuration.

These are fixed values, not settings: nothing legitimate comes near them, and a setting would be one more way to remove the protection.

We tried moving engine work off the proxy's worker threads with `block_in_place`. It did not help (92 ms with it reverted, 64 ms with it, in a run limited by the same quota), and blocking on the runtime's I/O driver is a known hazard, so it was removed.

**Authentication and sessions.**
- API tokens cannot create tokens. Otherwise a leaked, restricted token can mint an unrestricted successor.
- People change their own password with `POST /api/v1/auth/password`; their other sessions end.
- A successful login clears the per-name login count, and an address that has logged in passes the per-name limit, so guessing from elsewhere cannot lock a user out. The per-address limit still applies to it.
- Recovery codes have 125 random bits. At that strength a fast hash meets ASVS, which asks for a slow one below 112 bits.
- The dashboard marks requests made after a minute without user input (`X-RDock-Background`), and those do not refresh the idle timer. A client can only shorten its own session with it.

**Client addresses.** `X-Forwarded-For` on loopback is ignored unless `admin.trust_forwarded_on_loopback` is on. Any local process could otherwise claim an address, get past per-address limits and satisfy a token's `allowed_from`. ADR-0024's route to the admin listener needs the setting for real client addresses; without it those clients share one limit and token networks fail closed.

**Secrets.**
- Basic-auth hashes show as `name:***` and the v0.3 webhook URL as `***`. They are masked by the admin API, not added to the loader's secret fields, whose references resolve differently.
- A document written back with `***` keeps the current value, and is refused with `422` where there is none. The dashboard's editor saves whole documents, so it would otherwise store the literal `***`.
- Alert channels refuse URLs naming a private IP address directly: the connector skips the resolver for IP literals, so the guard from ADR-0024 never saw them.
- The CLI sends a token only to a loopback address, because it speaks plain HTTP.

**Audit.** `admin.audit.forward` gains `transport: tls` (RFC 5425) and `ca_file`. If TLS cannot be set up, forwarding stops with an error and records are never sent in clear text instead. Failed writes are counted in `rdock_admin_audit_write_failures_total`; the action still succeeds, so an audit fault cannot take the admin side down. The hash chain stays unkeyed: a key on the same machine and account does not stop whoever can rewrite the files. Forwarding off the machine is the tamper-resistant copy.

**Content Security Policy.** `style-src 'self'`, with no `unsafe-inline`. CodeMirror runs in a shadow root, where it uses constructed stylesheets instead of a `<style>` element.

## Consequences

- Under all of the above, with the admin side flooded, stalled or aborted, the proxy's p99 stays at baseline at 4,000 req/s on 2 CPUs. The isolation test enforces it.
- Scripts that exceed the limits get `429` and must honour `Retry-After`. Changing many objects belongs in one `PUT` or `PATCH`.
- Someone guessing from an address a user has logged in from is limited only by the per-address limit, 5 a minute; that is accepted, because the alternative lets anyone lock a user out.
- Dashboards left open with no input are logged out after the idle timeout, including ones meant to stay on a wall. A token-based tool is the answer for those.
- Validating needs the operator role, stricter than ADR-0024's table says; the code stands and the guide documents it.
- UDP and plain TCP forwarding remain options, because many syslog servers accept nothing else; only `tls` protects records on the network.
