//! A non-final attempt gives up connecting after `timeouts.connect_attempt` (ADR-0026).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use rdock_proxy::forwarded::CloudflareRanges;
use rdock_proxy::runtime::ServiceRuntime;
use rdock_proxy::upstream::{Dns, connect_budget};
use rdock_proxy::{CompileEnv, Mode, compile};

const FULL: Duration = Duration::from_secs(5);
const ATTEMPT: Duration = Duration::from_secs(1);

fn service(extra: &str) -> Arc<ServiceRuntime> {
    let yaml = format!(
        r#"
listeners:
  web: {{ address: ":8080" }}
defaults: {{ listeners: [web], tls: off }}
routes:
  app: {{ match: "PathPrefix(`/`)", service: app }}
services:
  app:
    backends: [{{ address: "10.0.0.1:80" }}, {{ address: "10.0.0.2:80" }}]
{extra}
"#
    );
    let config = rdock_config::load_str(&yaml, rdock_config::Format::Yaml)
        .unwrap()
        .config;
    let compiled = compile(
        &config,
        &CompileEnv {
            mode: Mode::Validate,
            generation: 1,
            dns: &Dns::default(),
            client: Arc::new(rdock_middleware::HttpClient::default()),
            previous: None,
            cloudflare: &CloudflareRanges::default(),
            backends: &rdock_balancer::Registry::default(),
            sticky_key: b"test",
            live: &rdock_observability::live::Live::default(),
            caches: None,
            plugins: &rdock_plugin_api::Registry::new(),
            metrics: None,
            quotas: None,
            abuse: None,
            shared_limits: None,
        },
    );
    let runtime = compiled.runtime.expect("compiles");
    runtime.services.get("app").unwrap().clone()
}

const RETRY_ON_CONNECT: &str = "    retries: { attempts: 2, on: [connect] }";

fn tried(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn the_default_retries_use_the_attempt_budget() {
    let service = service("");
    assert_eq!(
        connect_budget(FULL, &service, 0, &tried(&["10.0.0.1:80"])),
        ATTEMPT
    );
}

#[test]
fn an_attempt_that_can_be_retried_elsewhere_waits_connect_attempt() {
    let service = service(RETRY_ON_CONNECT);
    assert_eq!(
        connect_budget(FULL, &service, 0, &tried(&["10.0.0.1:80"])),
        ATTEMPT
    );
}

#[test]
fn the_last_backend_waits_the_full_connect_timeout() {
    let service = service(RETRY_ON_CONNECT);
    assert_eq!(
        connect_budget(FULL, &service, 1, &tried(&["10.0.0.1:80", "10.0.0.2:80"])),
        FULL,
        "every eligible backend was tried, so nothing is left to fall back to"
    );
}

#[test]
fn the_last_attempt_waits_the_full_connect_timeout() {
    let service = service(RETRY_ON_CONNECT);
    assert_eq!(
        connect_budget(FULL, &service, 2, &tried(&["10.0.0.1:80"])),
        FULL,
        "no retries left"
    );
}

#[test]
fn without_retries_on_connect_the_full_timeout_applies() {
    // No `retries` now means the connect defaults (ADR-0028); `attempts: 0` turns them off.
    for extra in [
        "    retries: { attempts: 0 }",
        "    retries: { attempts: 2, on: [\"503\"] }",
    ] {
        let service = service(extra);
        assert_eq!(
            connect_budget(FULL, &service, 0, &tried(&["10.0.0.1:80"])),
            FULL,
            "{extra:?}"
        );
    }
}

#[test]
fn a_shorter_connect_timeout_is_kept() {
    let service = service(RETRY_ON_CONNECT);
    let short = Duration::from_millis(300);
    assert_eq!(
        connect_budget(short, &service, 0, &tried(&["10.0.0.1:80"])),
        short
    );
}

#[test]
fn connect_attempt_is_configurable() {
    let service = service(&format!(
        "{RETRY_ON_CONNECT}\n    timeouts: {{ connect_attempt: 2s }}"
    ));
    assert_eq!(
        connect_budget(FULL, &service, 0, &tried(&["10.0.0.1:80"])),
        Duration::from_secs(2)
    );
}

#[test]
fn a_zero_connect_attempt_is_refused() {
    let yaml = r#"
services:
  app:
    backends: [{ address: "10.0.0.1:80" }]
    timeouts: { connect_attempt: 0s }
"#;
    let loaded = rdock_config::load_str(yaml, rdock_config::Format::Yaml).unwrap();
    let report = loaded.config.validate();
    assert!(
        report
            .iter()
            .any(|d| d.is_error() && d.path.contains("timeouts.connect_attempt")),
        "{report:?}"
    );
}
