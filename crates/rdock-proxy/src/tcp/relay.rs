//! The byte relay of a TCP route: both directions at once, a half-close passed on, an idle
//! timeout reset by traffic in either direction, and a termination delay once one direction
//! has ended (ADR-0026).
//!
//! `tokio::io::copy_bidirectional` would wait for both directions forever and does not show
//! activity, so the two copy loops are ours: each reads, writes, flushes and notes the time;
//! end of stream on one side becomes a write shutdown (TCP `FIN`, or TLS `close_notify`) on the
//! other.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rdock_observability::IntCounter;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Read buffer of each direction.
const CHUNK: usize = 16 * 1024;

/// How long a relay may run quietly and wind down.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// No data in either direction for this long closes both sides.
    pub idle: Duration,
    /// After one direction ends, the other gets this long before both are closed.
    pub termination_delay: Duration,
}

/// Byte counters of the two directions.
#[derive(Debug, Clone)]
pub struct Counters {
    /// Bytes from the client to the backend.
    pub inbound: IntCounter,
    /// Bytes from the backend to the client.
    pub outbound: IntCounter,
}

/// How a relay ended.
#[derive(Debug)]
pub enum End {
    /// Both directions finished, or the termination delay ran out after one did.
    Finished,
    /// No data moved for the idle timeout.
    Idle,
    /// Reading or writing failed; both sides were closed at once.
    Failed(io::Error),
}

/// The time of the last data, shared by both directions.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

/// Relays between `client` and `backend` until both directions end, one fails, or the
/// connection is idle for `limits.idle`.
pub async fn relay<C, B>(client: C, backend: B, limits: Limits, counters: &Counters) -> End
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut backend_read, mut backend_write) = tokio::io::split(backend);
    let activity = Activity::new();
    let upstream = pump(
        &mut client_read,
        &mut backend_write,
        &activity,
        &counters.inbound,
    );
    let downstream = pump(
        &mut backend_read,
        &mut client_write,
        &activity,
        &counters.outbound,
    );
    let idle = idle(&activity, limits.idle);
    tokio::pin!(upstream, downstream, idle);
    let (first, upstream_left) = tokio::select! {
        result = &mut upstream => (result, false),
        result = &mut downstream => (result, true),
        () = &mut idle => return End::Idle,
    };
    if let Err(e) = first {
        return End::Failed(e);
    }
    let other = async {
        if upstream_left {
            upstream.await
        } else {
            downstream.await
        }
    };
    tokio::select! {
        result = other => result.map_or_else(End::Failed, |()| End::Finished),
        () = tokio::time::sleep(limits.termination_delay) => End::Finished,
        () = &mut idle => End::Idle,
    }
}

/// Copies `from` to `to` until `from` ends, then shuts down `to` for writing.
async fn pump<R, W>(
    from: &mut R,
    to: &mut W,
    activity: &Activity,
    bytes: &IntCounter,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return to.shutdown().await;
        }
        activity.touch();
        let chunk = buf.get(..n).unwrap_or_default();
        to.write_all(chunk).await?;
        to.flush().await?;
        bytes.inc_by(u64::try_from(n).unwrap_or(u64::MAX));
        activity.touch();
    }
}

/// Returns once nothing has moved for `limit`.
async fn idle(activity: &Activity, limit: Duration) {
    loop {
        let deadline = activity.last() + limit;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use tokio::io::{DuplexStream, duplex};

    use super::*;

    fn counters() -> Counters {
        Counters {
            inbound: IntCounter::new("in", "in").unwrap(),
            outbound: IntCounter::new("out", "out").unwrap(),
        }
    }

    const LIMITS: Limits = Limits {
        idle: Duration::from_secs(5),
        termination_delay: Duration::from_millis(100),
    };

    /// A relay between two in-memory pipes; returns the far ends (client, backend).
    fn start(
        limits: Limits,
        counters: &Counters,
    ) -> (DuplexStream, DuplexStream, tokio::task::JoinHandle<End>) {
        let (client, client_side) = duplex(1024);
        let (backend_side, backend) = duplex(1024);
        let counters = counters.clone();
        let task =
            tokio::spawn(async move { relay(client_side, backend_side, limits, &counters).await });
        (client, backend, task)
    }

    #[tokio::test]
    async fn relays_both_ways_and_passes_a_half_close_on() {
        let counters = counters();
        let (mut client, mut backend, task) = start(LIMITS, &counters);
        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        backend.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping", "the backend sees the client's end of stream");
        // The client stopped sending but still receives the reply.
        backend.write_all(b"pong").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"pong");
        assert!(matches!(task.await.unwrap(), End::Finished));
        assert_eq!(counters.inbound.get(), 4);
        assert_eq!(counters.outbound.get(), 4);
    }

    #[tokio::test]
    async fn the_termination_delay_bounds_the_other_direction() {
        let (mut client, _backend, task) = start(LIMITS, &counters());
        client.shutdown().await.unwrap();
        // The backend keeps its side open and silent.
        let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(matches!(ended, Ok(Ok(End::Finished))), "{ended:?}");
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"");
    }

    #[tokio::test]
    async fn an_idle_connection_is_closed_and_traffic_keeps_it_open() {
        let limits = Limits {
            idle: Duration::from_millis(300),
            termination_delay: Duration::from_millis(100),
        };
        let (mut client, mut backend, task) = start(limits, &counters());
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            client.write_all(b"x").await.unwrap();
            let mut one = [0u8; 1];
            backend.read_exact(&mut one).await.unwrap();
        }
        assert!(!task.is_finished(), "traffic resets the idle timer");
        let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(matches!(ended, Ok(Ok(End::Idle))), "{ended:?}");
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
    }
}
