//! Our own `GET /tasks` client (ADR-0026).
//!
//! bollard 0.21.1's `Task` has no `NetworksAttachments`, the field that holds a task's
//! addresses (bollard#767, open on 2026-11-06), so tasks are read with one plain request over
//! the endpoint bollard uses, deserialising only the fields the provider reads. Revisit when a
//! bollard release exposes the field.
//!
//! The request names API version 1.44 (Engine 25): every Engine from 25 on accepts it,
//! including 29.0–29.2, whose minimum was 1.44 before 29.3 lowered it to 1.40, and the task
//! fields read here have not changed since. bollard itself sends its own default version.

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::{Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use rdock_provider_docker::watch::{EngineAddress, REQUEST_TIMEOUT_SECS};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

/// The Engine API version in the request path.
const API_VERSION: &str = "v1.44";
/// Desired states of the tasks to list: `shutdown` and `remove` keep tasks that Swarm is
/// stopping in the list while they still run, so they can be drained instead of vanishing.
const DESIRED_STATES: [&str; 3] = ["running", "shutdown", "remove"];
/// Largest response accepted (about 20,000 tasks).
const MAX_BODY: usize = 64 * 1024 * 1024;

/// A task, with the fields the provider reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Task {
    /// Task ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// ID of the service the task belongs to.
    #[serde(rename = "ServiceID")]
    pub service_id: String,
    /// Replica number of a replicated service; global services have none.
    #[serde(rename = "Slot", default)]
    pub slot: Option<u64>,
    /// What Swarm wants the task to be: `running`, or `shutdown`/`remove` while stopping it.
    #[serde(rename = "DesiredState", default)]
    pub desired_state: String,
    /// What the task is.
    #[serde(rename = "Status", default)]
    pub status: TaskStatus,
    /// The task's address on each network it is attached to.
    #[serde(rename = "NetworksAttachments", default)]
    pub networks_attachments: Option<Vec<NetworkAttachment>>,
}

/// A task's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TaskStatus {
    /// `running` once the container runs and its health check, if any, passed.
    #[serde(rename = "State", default)]
    pub state: String,
}

/// A task's attachment to one network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NetworkAttachment {
    /// The network.
    #[serde(rename = "Network")]
    pub network: AttachedNetwork,
    /// The task's addresses on it, in CIDR form (`10.0.1.5/24`).
    #[serde(rename = "Addresses", default)]
    pub addresses: Option<Vec<String>>,
}

/// The network of an attachment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttachedNetwork {
    /// Network ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// The network's name.
    #[serde(rename = "Spec")]
    pub spec: AttachedNetworkSpec,
}

/// The part of a network's spec the provider reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttachedNetworkSpec {
    /// Network name.
    #[serde(rename = "Name")]
    pub name: String,
}

/// Lists running tasks and the ones Swarm is stopping.
pub async fn list(address: &EngineAddress) -> Result<Vec<Task>, String> {
    let filters = serde_json::json!({ "desired-state": DESIRED_STATES }).to_string();
    let query: String = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("filters", &filters)
        .finish();
    let body = get(address, &format!("/{API_VERSION}/tasks?{query}")).await?;
    serde_json::from_slice(&body).map_err(|err| format!("cannot read the task list: {err}"))
}

/// One GET on a new connection, bounded by the Engine API timeout.
async fn get(address: &EngineAddress, path: &str) -> Result<Bytes, String> {
    let request = async {
        match address {
            EngineAddress::Unix(socket) => {
                let stream = UnixStream::connect(socket)
                    .await
                    .map_err(|err| format!("cannot connect to {socket}: {err}"))?;
                send(stream, "localhost", path).await
            }
            EngineAddress::Tcp(host) => {
                let stream = TcpStream::connect(host)
                    .await
                    .map_err(|err| format!("cannot connect to {host}: {err}"))?;
                send(stream, host, path).await
            }
        }
    };
    let timeout = std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS);
    tokio::time::timeout(timeout, request)
        .await
        .map_err(|_| format!("GET {path} timed out after {REQUEST_TIMEOUT_SECS} s"))?
}

async fn send<S>(stream: S, host: &str, path: &str) -> Result<Bytes, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let fail = |err: hyper::Error| format!("GET {path}: {err}");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(fail)?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::debug!(error = %err, "Engine API connection closed with an error");
        }
    });
    let request = Request::get(path)
        .header(header::HOST, host)
        .body(Empty::<Bytes>::new())
        .map_err(|err| format!("GET {path}: {err}"))?;
    let response = sender.send_request(request).await.map_err(fail)?;
    let status = response.status();
    let body = Limited::new(response.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|err| format!("GET {path}: {err}"))?
        .to_bytes();
    if status != StatusCode::OK {
        return Err(format!("GET {path}: {status}: {}", engine_message(&body)));
    }
    Ok(body)
}

/// The Engine API's `{"message": …}` error text, else the body as text.
fn engine_message(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct EngineError {
        message: String,
    }
    serde_json::from_slice::<EngineError>(body).map_or_else(
        |_| String::from_utf8_lossy(body).trim().to_owned(),
        |error| error.message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_errors_show_their_message() {
        assert_eq!(
            engine_message(br#"{"message":"This node is not a swarm manager."}"#),
            "This node is not a swarm manager."
        );
        assert_eq!(engine_message(b"bad gateway\n"), "bad gateway");
    }

    #[test]
    fn tasks_without_attachments_or_slot_decode() {
        let tasks: Vec<Task> = serde_json::from_str(
            r#"[{"ID":"t1","ServiceID":"s1","DesiredState":"running","Status":{"State":"running"},"NetworksAttachments":null}]"#,
        )
        .unwrap();
        assert_eq!(tasks[0].slot, None);
        assert_eq!(tasks[0].networks_attachments, None);
    }

    #[tokio::test]
    async fn requests_name_the_api_version_and_filters() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = EngineAddress::Tcp(listener.local_addr().unwrap().to_string());
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0; 4096];
            let n = socket.read(&mut buffer).await.unwrap();
            let body = "[]";
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..n]).into_owned()
        });
        assert_eq!(list(&address).await.unwrap(), Vec::new());
        let request = server.await.unwrap();
        let line = request.lines().next().unwrap();
        assert!(line.starts_with("GET /v1.44/tasks?filters="), "{line}");
        assert!(line.contains("desired-state"), "{line}");
    }
}
