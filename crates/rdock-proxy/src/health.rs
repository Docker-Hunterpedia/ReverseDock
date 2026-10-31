//! Active health checks: one background task per service with `health.active`, probing every
//! backend address over HTTP, TCP or the gRPC health protocol (ADR-0022). Results go into the
//! backend state shared across generations; the request path only reads them.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pingora::http::RequestHeader;
use rdock_balancer::Availability;
use rdock_middleware::HttpClient;
use rdock_model::route::RouteTimeouts;
use rdock_model::service::HealthMode;
use rdock_observability::Metrics;
use tokio::task::JoinSet;

use crate::runtime::{ActiveCheck, Candidate, Member, Runtime, ServiceRuntime};
use crate::upstream;

/// Largest probe response body read.
const MAX_BODY: usize = 64 * 1024;
const GRPC_HEALTH_PATH: &str = "/grpc.health.v1.Health/Check";

/// The running probe tasks.
#[derive(Debug, Default)]
pub(crate) struct Checkers {
    tasks: Mutex<JoinSet<()>>,
}

impl Checkers {
    /// Replaces the probe tasks with those of `runtime`. Backend state is shared across
    /// generations, so restarting the tasks keeps every verdict.
    pub(crate) fn restart(&self, runtime: &Runtime, client: &Arc<HttpClient>, metrics: &Metrics) {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        tasks.abort_all();
        for service in runtime.services.values() {
            if let Some(check) = service.health.active.clone() {
                tasks.spawn(run(service.clone(), check, client.clone(), metrics.clone()));
            }
        }
    }
}

async fn run(
    service: Arc<ServiceRuntime>,
    check: ActiveCheck,
    client: Arc<HttpClient>,
    metrics: Metrics,
) {
    let check = Arc::new(check);
    loop {
        let mut probes = JoinSet::new();
        for member in service.members().iter().cloned() {
            let (service, check, client) = (service.clone(), check.clone(), client.clone());
            probes.spawn(async move {
                let ok = probe(&service, &member, &check, &client).await;
                (member, ok)
            });
        }
        while let Some(Ok((member, ok))) = probes.join_next().await {
            record(&service, &member, &check, ok, &metrics);
        }
        tokio::time::sleep(jittered(check.interval)).await;
    }
}

fn record(
    service: &ServiceRuntime,
    member: &Member,
    check: &ActiveCheck,
    ok: bool,
    metrics: &Metrics,
) {
    let now = Instant::now();
    match member.state.probe(ok, check.policy, now) {
        Some(true) => {
            tracing::info!(service = %service.name, backend = %member.id, "backend is healthy");
            metrics.feeds.events.send(serde_json::json!({
                "type": "backend", "service": &*service.name, "backend": member.id, "state": "up",
                "reason": "passed its health checks",
            }));
        }
        Some(false) => {
            tracing::warn!(service = %service.name, backend = %member.id, "backend failed its health checks");
            metrics.feeds.events.send(serde_json::json!({
                "type": "backend", "service": &*service.name, "backend": member.id, "state": "down",
                "reason": "failed its health checks",
            }));
        }
        None => {}
    }
    let up = member.state.availability(now) != Availability::Down;
    metrics
        .backend_up
        .with_label_values(&[&*service.name, &member.id])
        .set(i64::from(up));
}

/// `interval` ± 10 %, so probes of many instances do not line up.
fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(0.9 + fastrand::f64() * 0.2)
}

async fn probe(
    service: &ServiceRuntime,
    member: &Member,
    check: &ActiveCheck,
    client: &HttpClient,
) -> bool {
    let candidate = match (&member.candidate, check.port) {
        (Candidate::Tcp { host, addr }, Some(port)) => {
            let mut addr = *addr;
            addr.set_port(port);
            Candidate::Tcp {
                host: host.clone(),
                addr,
            }
        }
        (candidate, _) => candidate.clone(),
    };
    let result = match check.mode {
        HealthMode::Tcp => tcp(&candidate, check.timeout).await,
        HealthMode::Http => http(service, &candidate, check, client).await,
        HealthMode::Grpc => grpc(service, &candidate, check, client).await,
    };
    if let Err(why) = &result {
        tracing::debug!(service = %service.name, backend = %member.id, %why, "health probe failed");
    }
    result.is_ok()
}

async fn tcp(candidate: &Candidate, timeout: Duration) -> Result<(), String> {
    let connect = async {
        match candidate {
            Candidate::Tcp { addr, .. } => tokio::net::TcpStream::connect(addr).await.map(drop),
            Candidate::Unix(path) => tokio::net::UnixStream::connect(path).await.map(drop),
        }
    };
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".to_owned()),
    }
}

fn probe_peer(
    service: &ServiceRuntime,
    candidate: &Candidate,
    timeout: Duration,
) -> Result<pingora::upstreams::peer::HttpPeer, String> {
    let ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let t = Some(rdock_model::values::Duration::from_millis(ms));
    let timeouts = RouteTimeouts {
        connect: t,
        read: t,
        write: t,
    };
    upstream::peer(service, candidate, &timeouts).map_err(|e| e.to_string())
}

fn probe_request(
    service: &ServiceRuntime,
    candidate: &Candidate,
    check: &ActiveCheck,
    method: &http::Method,
    path: &str,
) -> Result<RequestHeader, String> {
    let mut req =
        RequestHeader::build(method.clone(), path.as_bytes(), None).map_err(|e| e.to_string())?;
    let host = check
        .hostname
        .clone()
        .unwrap_or_else(|| crate::proxy::backend_authority(service.scheme, candidate));
    req.insert_header(http::header::HOST, host)
        .map_err(|e| e.to_string())?;
    req.insert_header(http::header::USER_AGENT, "rdock-health-check")
        .map_err(|e| e.to_string())?;
    Ok(req)
}

async fn http(
    service: &ServiceRuntime,
    candidate: &Candidate,
    check: &ActiveCheck,
    client: &HttpClient,
) -> Result<(), String> {
    let peer = probe_peer(service, candidate, check.timeout)?;
    let mut req = probe_request(service, candidate, check, &check.method, &check.path)?;
    for (name, value) in &check.headers {
        req.insert_header(name.clone(), value.clone())
            .map_err(|e| e.to_string())?;
    }
    let reply = client
        .send(&peer, req, check.timeout, MAX_BODY)
        .await
        .map_err(|e| e.to_string())?;
    let status = reply.header.status.as_u16();
    let (from, to) = check.expected_status;
    if !(from..=to).contains(&status) {
        return Err(format!("status {status}"));
    }
    if let Some(text) = &check.expected_body
        && !String::from_utf8_lossy(&reply.body).contains(text.as_str())
    {
        return Err("the body does not contain `expected_body`".to_owned());
    }
    Ok(())
}

async fn grpc(
    service: &ServiceRuntime,
    candidate: &Candidate,
    check: &ActiveCheck,
    client: &HttpClient,
) -> Result<(), String> {
    let peer = probe_peer(service, candidate, check.timeout)?;
    let mut req = probe_request(
        service,
        candidate,
        check,
        &http::Method::POST,
        GRPC_HEALTH_PATH,
    )?;
    req.insert_header(http::header::CONTENT_TYPE, "application/grpc")
        .map_err(|e| e.to_string())?;
    req.insert_header(http::header::TE, "trailers")
        .map_err(|e| e.to_string())?;
    let body = grpc_request(&check.grpc_service);
    let (reply, trailers) = client
        .send_with_body(&peer, req, body, check.timeout, MAX_BODY)
        .await
        .map_err(|e| e.to_string())?;
    if reply.header.status != 200 {
        return Err(format!("status {}", reply.header.status.as_u16()));
    }
    // A "trailers-only" answer carries grpc-status in the headers.
    let grpc_status = trailers
        .as_ref()
        .and_then(|t| t.get("grpc-status"))
        .or_else(|| reply.header.headers.get("grpc-status"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    if grpc_status != "0" {
        return Err(format!("grpc-status {grpc_status}"));
    }
    match grpc_serving_status(&reply.body) {
        Some(1) => Ok(()),
        other => Err(format!("serving status {other:?}")),
    }
}

/// A length-prefixed `HealthCheckRequest { string service = 1; }`.
fn grpc_request(service: &str) -> Bytes {
    let mut message = Vec::new();
    if !service.is_empty() {
        message.push(0x0a);
        push_varint(&mut message, service.len() as u64);
        message.extend_from_slice(service.as_bytes());
    }
    let mut frame = vec![0];
    frame.extend_from_slice(
        &u32::try_from(message.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let low = (value & 0x7f).to_le_bytes()[0];
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn read_varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes.split_first()?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The `status` of a length-prefixed `HealthCheckResponse` (0 when absent, as protobuf says).
fn grpc_serving_status(body: &[u8]) -> Option<u64> {
    let (&compressed, rest) = body.split_first()?;
    if compressed != 0 || rest.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let mut message = rest.get(4..4 + len)?;
    let mut status = 0;
    while !message.is_empty() {
        let tag = read_varint(&mut message)?;
        match tag & 7 {
            0 => {
                let value = read_varint(&mut message)?;
                if tag >> 3 == 1 {
                    status = value;
                }
            }
            2 => {
                let skip = usize::try_from(read_varint(&mut message)?).ok()?;
                message = message.get(skip..)?;
            }
            _ => return None,
        }
    }
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_messages_are_encoded_and_decoded() {
        assert_eq!(&grpc_request("")[..], &[0, 0, 0, 0, 0]);
        assert_eq!(
            &grpc_request("api")[..],
            &[0, 0, 0, 0, 5, 0x0a, 3, b'a', b'p', b'i']
        );
        assert_eq!(grpc_serving_status(&[0, 0, 0, 0, 2, 0x08, 0x01]), Some(1));
        assert_eq!(grpc_serving_status(&[0, 0, 0, 0, 2, 0x08, 0x02]), Some(2));
        assert_eq!(
            grpc_serving_status(&[0, 0, 0, 0, 0]),
            Some(0),
            "an empty message is UNKNOWN"
        );
        // An unknown length-delimited field before the status is skipped.
        assert_eq!(
            grpc_serving_status(&[0, 0, 0, 0, 5, 0x12, 1, b'x', 0x08, 0x01]),
            Some(1)
        );
        assert_eq!(grpc_serving_status(&[1, 0, 0, 0, 0]), None, "compressed");
        assert_eq!(
            grpc_serving_status(&[0, 0, 0, 0, 9, 0x08]),
            None,
            "truncated"
        );
        assert_eq!(grpc_serving_status(&[]), None);
    }

    #[test]
    fn varints_round_trip() {
        for value in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            let mut out = Vec::new();
            push_varint(&mut out, value);
            assert_eq!(read_varint(&mut out.as_slice()), Some(value));
        }
    }

    #[test]
    fn jitter_stays_within_ten_percent() {
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(10));
            assert!(
                d >= Duration::from_secs(9) && d <= Duration::from_secs(11),
                "{d:?}"
            );
        }
    }
}
