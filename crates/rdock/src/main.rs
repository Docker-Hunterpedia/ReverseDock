//! The stock `rdock` binary: the library's command line with no native plugins. A binary with
//! plugins is the same call with a registry that lists them (see `rdock::run`).

use std::process::ExitCode;

fn main() -> ExitCode {
    rdock::run(rdock::Registry::new())
}
