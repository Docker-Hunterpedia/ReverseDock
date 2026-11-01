//! The cost of recording a request in a live ring (ADR-0024). `Ring::record` only does atomic
//! operations on slots allocated with the ring, so it takes no lock and allocates nothing; this
//! opt-in test measures it under contention:
//! `cargo test --release -p rdock-observability --test live_hot_path -- --ignored --nocapture`.

#![allow(clippy::unwrap_used, clippy::cast_precision_loss)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rdock_observability::live::{Ring, Sample};

fn sample(i: u64) -> Sample {
    Sample {
        status: [200, 304, 404, 502][(i % 4) as usize],
        elapsed: Duration::from_micros(40 + i * 37 % 900_000),
        bytes_in: i,
        bytes_out: 2 * i,
    }
}

#[test]
#[ignore = "a measurement; run with --release --ignored --nocapture"]
fn recording_costs_tens_of_nanoseconds() {
    let ring = Arc::new(Ring::default());
    let threads: u64 = std::env::var("THREADS")
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or(8);
    let per_thread: u64 = 2_000_000;
    let started = Instant::now();
    let workers: Vec<_> = (0..threads)
        .map(|t| {
            let ring = ring.clone();
            std::thread::spawn(move || {
                let now = SystemTime::now();
                for i in 0..per_thread {
                    ring.record(sample(i + t), now);
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    let per_op = started.elapsed().as_nanos() as f64 / per_thread as f64;
    println!(
        "{} records on {threads} threads, all into one slot: {per_op:.1} ns per record per thread",
        threads * per_thread
    );
}
