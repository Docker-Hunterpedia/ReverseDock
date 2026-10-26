# ADR-0016: `${…}` references in the configuration; secrets stay references

- Status: accepted · Date: 2026-10-26

## Context
B-CFG-03 asks for environment interpolation and file secrets (`${VAR}`, `${file:/run/secrets/x}`). Two parts of the model already use `$`: regular-expression replacements (`$1`, `${name}`), and secret fields whose validator expects a reference. A resolved secret must not end up in the configuration history, the last-known-good copy, the admin API or error messages.

## Decision
- In string values, `${NAME}` and `${env:NAME}` are replaced by an environment variable and `${file:/absolute/path}` by a file's contents (at most 64 KiB, one trailing newline removed). `$${` writes a literal `${`. A missing variable or file is an error at that path. Replaced text is never expanded again.
- `replacement` fields of middlewares are taken literally, so `$1` and `${name}` keep referring to capture groups.
- Secret fields (`acme.dns_providers.*.api_token`, `acme.eab.hmac_key`, `certificates.*.key_password`) keep the reference in the loaded configuration and are resolved by the component that uses them. The list lives in `rdock_model::interpolation`.
- The loader keeps the document as written (`Loaded::source`); history and the last-known-good copy store that form. When a value from a reference fails to parse, the error does not quote it.
- Unknown keys are errors, not warnings, so a misspelt security setting cannot be ignored silently; keys starting with `x-` are extension fields (YAML anchors) and are ignored. `rdock validate --strict` now means "warnings are errors".

## Consequences
- `rdock validate` in CI needs the referenced variables and files, or placeholders for them.
- Typed fields such as ports are interpolated as strings; references are meant for strings (hosts, addresses, tokens), which covers the documented uses.
