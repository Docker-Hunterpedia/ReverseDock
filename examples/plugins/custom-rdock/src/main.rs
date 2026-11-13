//! A ReverseDock binary with two plugins compiled in. Every `rdock` subcommand works as in the
//! stock binary; `type: plugin` middlewares may name `header_rewrite` and `ip_blocklist`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let registry = rdock::Registry::new()
        .plugin("header_rewrite", header_rewrite::factory())
        .plugin("ip_blocklist", ip_blocklist::factory());
    rdock::run(registry)
}
