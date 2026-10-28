//! A small HTTPS client for webhooks: JSON `POST` with an optional bearer token.

use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::Full;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rdock_model::acme::Webhook;

/// Why a webhook call failed.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The token reference could not be resolved.
    #[error("token: {0}")]
    Token(String),
    /// The request could not be built.
    #[error("request: {0}")]
    Request(#[from] http::Error),
    /// The endpoint could not be reached.
    #[error("cannot reach the endpoint: {0}")]
    Connect(#[from] hyper_util::client::legacy::Error),
    /// No answer within the timeout.
    #[error("no answer within {0:?}")]
    Timeout(Duration),
    /// The endpoint answered with an error status.
    #[error("the endpoint answered {0}")]
    Status(StatusCode),
    /// The OS trust store could not be loaded.
    #[error("TLS setup: {0}")]
    Tls(String),
}

/// A client for webhooks. HTTPS uses the operating system's trust store; plain HTTP is only
/// reached when validation allowed it (loopback addresses).
#[derive(Clone, Debug)]
pub struct WebhookClient {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl WebhookClient {
    /// A client with the platform's root certificates.
    pub fn new() -> Result<Self, WebhookError> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|e| WebhookError::Tls(e.to_string()))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        })
    }

    /// Sends `body` as JSON to `webhook`; any 2xx answer is success.
    pub async fn post(
        &self,
        webhook: &Webhook,
        body: &serde_json::Value,
    ) -> Result<StatusCode, WebhookError> {
        let mut request = Request::post(webhook.url.as_url().as_str())
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::USER_AGENT,
                concat!("rdock/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(token) = &webhook.token {
            let token = rdock_config::interpolate::expand(token, &rdock_config::System)
                .map_err(|e| WebhookError::Token(e.to_string()))?;
            request = request.header(header::AUTHORIZATION, format!("Bearer {}", token.trim()));
        }
        let request = request.body(Full::new(Bytes::from(body.to_string())))?;
        let timeout = webhook.timeout.as_std();
        let response = tokio::time::timeout(timeout, self.client.request(request))
            .await
            .map_err(|_| WebhookError::Timeout(timeout))??;
        let status = response.status();
        if status.is_success() {
            Ok(status)
        } else {
            Err(WebhookError::Status(status))
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn posts_json_with_the_bearer_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = [0; 4096];
            while !String::from_utf8_lossy(&received).contains("\"event\"") {
                let n = stream.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8_lossy(&received).into_owned()
        });
        let webhook = Webhook {
            url: format!("http://{addr}/hook").parse().unwrap(),
            token: Some("s3cret".to_owned()),
            timeout: rdock_model::values::Duration::from_secs(5),
        };
        let status = WebhookClient::new()
            .unwrap()
            .post(
                &webhook,
                &serde_json::json!({ "event": "certificate_expiring" }),
            )
            .await
            .unwrap();
        assert_eq!(status, StatusCode::NO_CONTENT);
        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("post /hook"), "{request}");
        assert!(
            request.contains("authorization: bearer s3cret"),
            "{request}"
        );
        assert!(
            request.contains("content-type: application/json"),
            "{request}"
        );
    }
}
