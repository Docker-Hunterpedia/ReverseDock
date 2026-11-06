# rdock-dns-providers

DNS-01 adapters behind `rdock-acme`'s `DnsSolver` trait ([ADR-0026](../../docs/decisions/0026-swarm-l4-static.md), W-DNS-03): `digitalocean`, `hetzner` (the Hetzner Cloud API) and `rfc2136` (dynamic updates with TSIG). `Providers` builds them from `acme.dns_providers` and hands every other `type` to the providers it wraps; the binary wraps the Cloudflare adapter, which wraps the built-in `exec` and `webhook`.

Shared pieces:

- a JSON client on the hyper-rustls client the Cloudflare adapter uses: platform verifier, no redirects, 30 s per attempt, at most 5 attempts with exponential backoff and full jitter, honouring `Retry-After` and, on `429`, `RateLimit-Reset`; a server asking for more than 30 s fails the call; API errors carry the provider's message, never the token;
- zone discovery: the closest name from the record up that the provider serves as a zone, remembered for the solver's life (one renewal pass), unless `zone` is set;
- secrets stay `${file:…}`/`${env:…}` references and are read for every call, so rotated files are used without a reload.

RFC 2136 builds messages with hickory-proto (`dnssec-ring`) and sends them over its own TCP or UDP socket; TSIG is signed and the server's answer verified with ring (HMAC-SHA256 by default, SHA-384/512, SHA-1 with a validation warning, MD5 refused). Present appends one TXT record, cleanup deletes that record by its data; the RRset is never deleted.

Every adapter runs `rdock_testkit::dns_contract` against a fake of its provider: `rdock_testkit::fake_api` for the HTTP APIs and an in-process UPDATE server that verifies TSIG for RFC 2136.

**Status:** v0.6. deSEC, Route 53, Google Cloud DNS and Azure DNS follow (#193).
