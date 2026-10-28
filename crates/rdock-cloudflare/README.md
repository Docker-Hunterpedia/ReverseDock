# rdock-cloudflare

Cloudflare integration: trusted IP range sync, the Cloudflare `DnsProvider` for DNS-01, Access JWT validation and Origin CA helpers.

The range sync ([ADR-0020](../../docs/decisions/0020-automatic-https.md)) loads `$RDOCK_DATA_DIR/cloudflare/ips.json`, or the list compiled into the binary when there is none, before the first configuration is applied, so startup never waits for the network. While a configuration trusts `cloudflare`, a background task fetches `https://api.cloudflare.com/client/v4/ips` once a day, keeps the list when its `etag` is unchanged, rejects implausible answers (no ranges, wrong families, ranges wider than /8 or /16) and keeps the current list when a fetch fails, trying again after an hour. The data plane reads the ranges through an `ArcSwap` and never waits for the task.

**Status:** IP range sync (W-CF-01) for `trusted_proxies: [cloudflare]` and `client_ip_header: cf-connecting-ip` (W-CF-02, v0.3). The DNS provider, Access and Origin CA follow. Requirements: W-CF-01 … W-CF-08 in [requirements](../../docs/04-requirements.md).
