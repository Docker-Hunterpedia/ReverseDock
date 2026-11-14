//! Allocation counting for the per-request measurement helper (`benchmarks/perreq`).
//!
//! Behind the bench-only `alloc-count` feature: the system allocator wrapped in atomic counters
//! (`stats_alloc`). When `RDOCK_ALLOC_COUNT_SOCKET` names a path, a plain thread listens on that
//! Unix socket and answers every connection with one line, `allocations deallocations
//! reallocations bytes_allocated`, then closes it. The helper reads it before and after a fixed
//! number of requests; the reads cost the same in every phase, so they cancel in its N/2N
//! difference.

#[cfg(not(debug_assertions))]
compile_error!(
    "the `alloc-count` feature is for measurement builds only; build it without --release"
);

use std::alloc::System;
use std::io::Write;
use std::os::unix::net::UnixListener;

use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static ALLOCATOR: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Starts the counter socket if `RDOCK_ALLOC_COUNT_SOCKET` is set; does nothing otherwise.
pub(crate) fn serve_from_env() {
    let Some(path) = std::env::var_os("RDOCK_ALLOC_COUNT_SOCKET") else {
        return;
    };
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("alloc-count: cannot bind {}: {err}", path.to_string_lossy());
            return;
        }
    };
    let spawned = std::thread::Builder::new()
        .name("alloc-count".into())
        .spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let stats = ALLOCATOR.stats();
                let _ = writeln!(
                    stream,
                    "{} {} {} {}",
                    stats.allocations,
                    stats.deallocations,
                    stats.reallocations,
                    stats.bytes_allocated
                );
            }
        });
    if let Err(err) = spawned {
        eprintln!("alloc-count: cannot start the counter thread: {err}");
    }
}
