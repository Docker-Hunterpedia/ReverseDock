//! Embeds build information: commit (from `RDOCK_BUILD_COMMIT` or `GITHUB_SHA`), compiler
//! version and target triple.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RDOCK_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let commit = std::env::var("RDOCK_BUILD_COMMIT")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .map_or_else(
            |_| "dev".to_owned(),
            |sha| sha.chars().take(12).collect::<String>(),
        );
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rustc_version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |v| v.trim().to_owned());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=RDOCK_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=RDOCK_BUILD_RUSTC={rustc_version}");
    println!("cargo:rustc-env=RDOCK_BUILD_TARGET={target}");
}
