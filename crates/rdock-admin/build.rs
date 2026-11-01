//! Rebuilds when the dashboard build output changes, so `pnpm build` followed by `cargo build`
//! embeds the new files (ADR-0024).

fn main() {
    println!("cargo:rerun-if-changed=../../apps/dashboard/dist");
}
