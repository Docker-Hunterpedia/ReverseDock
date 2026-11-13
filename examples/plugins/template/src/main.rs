//! `my-rdock`: the stock command line with `my_plugin` registered as `greeting`.

use std::process::ExitCode;

fn main() -> ExitCode {
    rdock::run(rdock::Registry::new().plugin("greeting", my_plugin::factory()))
}
