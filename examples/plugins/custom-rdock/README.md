# custom-rdock

A ReverseDock binary with the [`header-rewrite`](../header-rewrite/README.md) and [`ip-blocklist`](../ip-blocklist/README.md) plugins compiled in. Its whole `main`:

```rust
use std::process::ExitCode;

fn main() -> ExitCode {
    let registry = rdock::Registry::new()
        .plugin("header_rewrite", header_rewrite::factory())
        .plugin("ip_blocklist", ip_blocklist::factory());
    rdock::run(registry)
}
```

Every subcommand works as in the stock `rdock` (`run`, `validate`, `schema`, `reload`…), with the plugins available to `type: plugin` middlewares and to `validate`; `custom-rdock version` lists them. `cargo test -p custom-rdock` starts the binary with a configuration that uses both plugins and checks that they act on real HTTP/1.1 and HTTP/2 requests, that `validate` reports a plugin's configuration error with its path (`middlewares.blocklist.config.deny[0]`) and an unknown plugin name with the registered ones.

Build a release binary with `cargo build --release -p custom-rdock` (needs a C compiler and CMake, like `rdock`). For a container image, adapt the build stage of the repository's `Dockerfile` (`cargo build -p custom-rdock`, then install `target/release/custom-rdock`).
