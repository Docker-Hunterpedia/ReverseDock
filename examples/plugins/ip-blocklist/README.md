# ip-blocklist

An example plugin: refuses requests from client addresses in a list of networks with `403` (or another 4xx), with the proxy's standard page or a message of your own.

```yaml
middlewares:
  blocklist:
    type: plugin
    name: ip_blocklist
    config:
      deny: [203.0.113.0/24, "2001:db8:bad::/48", 198.51.100.7]
      message: "Your network is blocked.\n"   # optional
      status: 403                             # optional
```

It checks the client address rdock resolved (after `trusted_proxies`), never a header the client controls. It shows:

- configuration errors with paths: `deny[1]: "10.1.2.3/8" has host bits set`, `status: 500 is not a 4xx status`, type errors from the typed factory (`deny[1]: invalid type…`);
- per-request state: the `request` phase stores the matched network, the `log` phase reads it and counts the refusal (`blocked()`, `last_blocked()`).

Tests: `cargo test -p ip-blocklist`. The built-in `ip_deny` middleware does the same job; this plugin shows how one is written.
