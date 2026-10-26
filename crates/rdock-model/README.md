# rdock-model

The desired-state model of ReverseDock: the Rust types behind `rdock.yaml`, their semantic validation, and the JSON Schema generated from them.

- **Types** mirror [architecture §3](../../docs/05-architecture.md): listeners, routes, services, middlewares, TCP routes and services, certificates, ACME, providers, security, admin and observability. The model is a superset of Traefik's dynamic configuration ([ADR-0003](../../docs/decisions/0003-config-model-superset-of-traefik.md)).
- **Values** such as durations (`10s`, `1h30m`), sizes (`32KiB`), listen addresses (`:443`), backend addresses (`app:3000`, `unix:///run/app.sock`) and IP networks are parsed into typed values when the configuration is deserialised.
- **Validation** (`Config::validate`) reports `Diagnostic`s with a path such as `routes.app.service`, a message and an optional hint: broken references, invalid rules, conflicting listeners, unsafe settings.
- **JSON Schema** (`json_schema`) is generated from the types and committed as [`schema/rdock.v1.json`](../../schema/rdock.v1.json); a test fails when it is out of date (`just schema` regenerates it).

Loading files, interpolation and merging live in `rdock-config`.
