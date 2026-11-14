//! CPU scaling (H-PERF-01, ADR-0031 step 9): the throughput and the CPU time per request of one
//! `rdock` pinned to a number of CPUs, with the worker threads set to match.
//!
//! The load is **closed-loop saturation**: a fixed number of kept-alive connections, each sending
//! the next request as soon as the last answer is in, so rdock is the limit. That measures peak
//! throughput and the CPU a request costs at that point; it says nothing about latency (a
//! closed loop hides a stalling proxy's tail, which the open-model k6 runs and the soak
//! measure instead). rdock's CPU time is read from `/proc/<pid>/task/*/schedstat` over the
//! measured phase, as `measure --measure cpu` does.
//!
//! Besides the numbers it reports how busy rdock's CPUs and the tool's were. A scaling figure is
//! only meaningful when rdock's CPUs were nearly all busy (`rdock_cpu_util`) and the tool's were
//! not the limit (`tool_cpu_util`, where the tool is the client and the backend together). When
//! the tool shares CPUs with rdock (the whole-machine size), its use is *inside* the CPUs that
//! rdock needs, and the result is a lower bound.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Args;

use crate::{Lab, LabArgs, request_bytes};

#[derive(Args)]
pub(crate) struct ScaleArgs {
    #[command(flatten)]
    pub(crate) lab: LabArgs,
    /// Kept-alive client connections, many more than rdock has CPUs.
    #[arg(long, default_value_t = 64)]
    conns: usize,
    /// Seconds of warm-up before the measured phase (connections stay open).
    #[arg(long, default_value_t = 5)]
    warmup: u64,
    /// Seconds of the measured phase.
    #[arg(long, default_value_t = 20)]
    seconds: u64,
    /// Worker threads of this tool's runtime (set to the CPUs it may use).
    #[arg(long, default_value_t = 2)]
    pub(crate) tool_threads: usize,
    /// The CPUs this tool runs on, as `taskset -c` takes them, to compute how busy they were.
    #[arg(long)]
    tool_cpus: Option<String>,
    /// A name for the variant, copied into the output.
    #[arg(long, default_value = "")]
    label: String,
}

/// How many CPUs a `taskset -c` list names (`0,1`, `2-3`, `0-3`, `0,2-3`).
fn cpu_count(list: &str) -> anyhow::Result<usize> {
    let mut total = 0;
    for part in list.split(',') {
        if let Some((a, b)) = part.split_once('-') {
            total += b.trim().parse::<usize>()? + 1 - a.trim().parse::<usize>()?;
        } else {
            part.trim().parse::<usize>()?;
            total += 1;
        }
    }
    anyhow::ensure!(total > 0, "empty CPU list");
    Ok(total)
}

/// Nanoseconds on a CPU, summed over this process's threads.
fn own_cpu_ns() -> anyhow::Result<u64> {
    let mut total = 0;
    for task in std::fs::read_dir("/proc/self/task")? {
        if let Ok(text) = std::fs::read_to_string(task?.path().join("schedstat"))
            && let Some(ns) = text.split_whitespace().next()
        {
            total += ns.parse::<u64>()?;
        }
    }
    Ok(total)
}

pub(crate) async fn run(args: ScaleArgs) -> anyhow::Result<()> {
    let rdock_cpus = match &args.lab.cpus {
        Some(list) => cpu_count(list)?,
        None => std::thread::available_parallelism()?.get(),
    };
    let tool_cpus = match &args.tool_cpus {
        Some(list) => cpu_count(list)?,
        None => std::thread::available_parallelism()?.get(),
    };
    let lab = Lab::start(&args.lab).await?;
    let request = Arc::new(request_bytes("site0.test", 3));
    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::with_capacity(args.conns);
    for _ in 0..args.conns {
        let mut conn = lab.connect("site0.test").await?;
        let (request, stop, done, errors) =
            (request.clone(), stop.clone(), done.clone(), errors.clone());
        tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(200) = conn.send(&request).await {
                    done.fetch_add(1, Ordering::Relaxed);
                } else {
                    errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }));
    }
    tokio::time::sleep(Duration::from_secs(args.warmup)).await;
    let (n0, e0) = (done.load(Ordering::Relaxed), errors.load(Ordering::Relaxed));
    let (rdock0, tool0, t0) = (lab.cpu_ns()?, own_cpu_ns()?, Instant::now());
    tokio::time::sleep(Duration::from_secs(args.seconds)).await;
    let (n1, e1) = (done.load(Ordering::Relaxed), errors.load(Ordering::Relaxed));
    let (rdock1, tool1, wall) = (lab.cpu_ns()?, own_cpu_ns()?, t0.elapsed());
    stop.store(true, Ordering::Relaxed);
    for task in tasks {
        let _ = task.await;
    }
    let requests = (n1 - n0) as f64;
    let wall_ns = wall.as_secs_f64() * 1e9;
    let rdock_ns = (rdock1 - rdock0) as f64;
    let tool_ns = (tool1 - tool0) as f64;
    let line = serde_json::json!({
        "label": args.label,
        "rdock_cpus": rdock_cpus,
        "tool_cpus": tool_cpus,
        "conns": args.conns,
        "seconds": wall.as_secs_f64(),
        "requests": n1 - n0,
        "errors": e1 - e0,
        "req_per_s": requests / wall.as_secs_f64(),
        "rdock_cpu_us_per_req": rdock_ns / requests / 1000.0,
        "rdock_cpu_util": rdock_ns / wall_ns / rdock_cpus as f64,
        "tool_cpu_util": tool_ns / wall_ns / tool_cpus as f64,
        "config_extra": args.lab.config_extra,
    });
    println!("{line}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cpu_count;

    #[test]
    fn counts_cpu_lists() {
        assert_eq!(cpu_count("0").unwrap(), 1);
        assert_eq!(cpu_count("0,1").unwrap(), 2);
        assert_eq!(cpu_count("1-3").unwrap(), 3);
        assert_eq!(cpu_count("0-3").unwrap(), 4);
        assert_eq!(cpu_count("0,2-3").unwrap(), 3);
        assert!(cpu_count("").is_err());
        assert!(cpu_count("a").is_err());
    }
}
