# rdock

The ReverseDock binary.

| Command | Since | What it does |
|---|---|---|
| `rdock validate <files>… [--strict] [--format text\|json]` | M0 | Loads and validates configuration files; exit code 1 when any has errors |
| `rdock schema` | M0 | Prints the JSON Schema of `rdock.yaml` |
| `rdock version [--json]` | M0 | Prints version, commit, compiler and target |
| `rdock run`, `reload`, `status`, `config`, `cert`, `migrate`, `trust` | v0.1+ | See [requirements B-CFG-04](../../docs/04-requirements.md) |
