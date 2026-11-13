# rdock-credentials

The credential formats ReverseDock issues, in one place both the admin API and the data plane
may use (ADR-0009 keeps the data plane off `rdock-admin`; ADR-0030 moved this code here):

- **Admin API tokens** (ADR-0024): `rdk_pat_<10-char id>_<32-char secret><6-char checksum>`.
- **API keys** of consumers (F-GW-01, ADR-0030): `rdk_<12-char id>_<32-char secret><6-char checksum>`.

Both use the Base62 alphabet (`0-9A-Za-z`, so a key is one word for double-click selection and
needs no escaping in headers, URLs or YAML), a public ID for lookup, logs and revocation, a
secret of 190 bits (32 × log2 62), and a CRC32 in six Base62 characters so a mistyped or
made-up value is refused without a lookup, as GitHub's token format does. Only the ID and the
SHA-256 of the secret are ever stored; comparison is constant-time.
