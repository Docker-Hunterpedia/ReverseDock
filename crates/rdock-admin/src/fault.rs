//! Faults injected into the admin side for the isolation test (H-ENG-04), compiled only with
//! the `fault-injection` feature: release builds never contain them.
//!
//! `RDOCK_FAULT` names one fault, `KIND@DELAY` or `KIND@DELAY+DURATION` in seconds:
//! - `abort@15`: the admin runtime panics and stops for good;
//! - `stall@15+30`: every admin thread blocks for 30 seconds;
//! - `write-lock@15+30`: the binary holds the configuration-write lock for 30 seconds.

use std::time::Duration;

/// A fault and when it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// What happens.
    pub kind: Kind,
    /// Time from the start of rdock until it happens.
    pub delay: Duration,
    /// How long a stall or a held lock lasts.
    pub duration: Duration,
}

/// The faults on offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The admin runtime panics and stops.
    Abort,
    /// Every admin thread blocks.
    Stall,
    /// The configuration-write lock is held.
    WriteLock,
}

/// The fault `RDOCK_FAULT` asks for; a value that does not parse is ignored with a warning.
#[must_use]
pub fn from_env() -> Option<Fault> {
    let text = std::env::var("RDOCK_FAULT").ok()?;
    let fault = parse(&text);
    if let Some(fault) = fault {
        tracing::warn!(?fault, "fault injection is armed");
    } else {
        tracing::warn!(value = %text, "RDOCK_FAULT is not KIND@DELAY[+DURATION]");
    }
    fault
}

fn parse(text: &str) -> Option<Fault> {
    let (kind, timing) = text.split_once('@')?;
    let kind = match kind {
        "abort" => Kind::Abort,
        "stall" => Kind::Stall,
        "write-lock" => Kind::WriteLock,
        _ => return None,
    };
    let (delay, duration) = timing.split_once('+').unwrap_or((timing, "0"));
    Some(Fault {
        kind,
        delay: Duration::from_secs(delay.parse().ok()?),
        duration: Duration::from_secs(duration.parse().ok()?),
    })
}

/// Runs on the admin runtime's main future: waits, then aborts or stalls the runtime. Never
/// returns for `abort`; returns after the stall, or at once for faults of the binary.
pub(crate) async fn strike(fault: Fault, threads: usize) {
    tokio::time::sleep(fault.delay).await;
    match fault.kind {
        Kind::Abort => {
            tracing::warn!("fault injection: aborting the admin runtime");
            #[expect(clippy::panic, reason = "the fault being injected is a panic")]
            {
                panic!("fault injection: admin runtime aborted");
            }
        }
        Kind::Stall => {
            tracing::warn!(
                seconds = fault.duration.as_secs(),
                "fault injection: stalling the admin runtime"
            );
            for _ in 0..threads {
                tokio::spawn(async move { std::thread::sleep(fault.duration) });
            }
            // Blocks the thread that drives the listeners too.
            std::thread::sleep(fault.duration);
        }
        Kind::WriteLock => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kinds_and_timing() {
        assert_eq!(
            parse("stall@15+30"),
            Some(Fault {
                kind: Kind::Stall,
                delay: Duration::from_secs(15),
                duration: Duration::from_secs(30)
            })
        );
        assert_eq!(parse("abort@5").map(|f| f.duration), Some(Duration::ZERO));
        assert_eq!(
            parse("write-lock@1+2").map(|f| f.kind),
            Some(Kind::WriteLock)
        );
        assert_eq!(parse("crash@1"), None);
        assert_eq!(parse("stall@soon"), None);
        assert_eq!(parse("stall"), None);
    }
}
