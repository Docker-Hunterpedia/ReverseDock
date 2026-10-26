# rdock-rules

The routing rule grammar of ReverseDock. It is compatible with the [Traefik v3 rule syntax](https://doc.traefik.io/traefik/reference/routing-configuration/http/routing/rules-and-priority/), so `traefik.http.routers.*.rule` labels can be used unchanged.

```text
Host(`app.example.com`) && (PathPrefix(`/api`) || Header(`X-Api`, `1`)) && !ClientIP(`10.0.0.0/8`)
```

- **HTTP matchers:** `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `HeaderRegexp`, `Query` (one or two arguments), `QueryRegexp`, `ClientIP`.
- **TCP matchers:** `HostSNI`, `HostSNIRegexp`, `ClientIP`, `ALPN`.
- **Operators:** `!` binds tightest, then `&&`, then `||`; parentheses group.
- **Strings:** backticks (raw) or double quotes with the escapes `\\`, `\"`, `\n`, `\r`, `\t`.

`parse` turns a rule into an `Expr`; `Expr::validate` checks it for an HTTP or TCP route (regular expressions compile, paths start with `/`, hosts are valid, matchers fit the context). `Display` prints a canonical form that parses back to the same `Expr`, which the property tests verify. The default route priority is the rule's length in bytes, as in Traefik.

Matching requests against an `Expr` belongs to the router in `rdock-proxy` (v0.1).
