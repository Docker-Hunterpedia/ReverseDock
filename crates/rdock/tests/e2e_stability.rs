//! End-to-end: maturity levels and deprecations at run time (ADR-0033). The deprecation
//! registry's test entries (`RDOCK_TEST_DEPRECATIONS=1`, debug builds only) stand in for
//! deprecations that do not exist yet: a renamed key (`routes.<name>.rule`), a CLI flag and an
//! API operation; `observability.alerts.webhook` is the real one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;

use rdock_testkit::backend::Backend;
use rdock_testkit::client::{self, get};
use rdock_testkit::free_port;
use rdock_testkit::rdock::Rdock;

const RDOCK: &str = env!("CARGO_BIN_EXE_rdock");
const HOOK: [(&str, &str); 1] = [("RDOCK_TEST_DEPRECATIONS", "1")];

fn config(port: u16, backend: SocketAddr, deprecated: bool) -> String {
    let (key, alerts) = if deprecated {
        (
            "rule",
            "observability:\n  alerts:\n    webhook: { url: \"http://127.0.0.1:9/hook\" }\n",
        )
    } else {
        ("match", "")
    };
    format!(
        "listeners:\n  web: {{ address: \"127.0.0.1:{port}\" }}\ndefaults: {{ listeners: [web], tls: off }}\ncaches:\n  mem: {{ type: memory }}\nroutes:\n  app: {{ {key}: \"Host(`app.test`)\", service: app }}\nservices:\n  app: {{ backends: [{{ address: \"{backend}\" }}] }}\n{alerts}"
    )
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn count(log: &str, needle: &str) -> usize {
    log.lines().filter(|l| l.contains(needle)).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deprecations_and_maturity_are_reported_at_run_time() {
    let backend = Backend::start("stable").await;
    let port = free_port();
    let mut rdock = Rdock::try_start_with_env(RDOCK, &config(port, backend.addr, true), &HOOK)
        .unwrap_or_else(|log| panic!("rdock did not start:\n{log}"));
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));

    // The renamed key keeps working during its overlap.
    let reply = client::http1(proxy, get("app.test", "/")).await;
    assert_eq!(reply.status, 200, "{}", rdock.log());

    // One WARN per deprecated element, one INFO per beta feature.
    let log = rdock.log();
    assert_eq!(count(&log, "deprecated configuration in use"), 2, "{log}");
    assert_eq!(count(&log, "routes.*.rule"), 1, "{log}");
    // `alerts` (the webhook) and `http-cache`.
    assert_eq!(count(&log, "beta feature in use"), 2, "{log}");
    assert!(log.contains("\"feature\":\"http-cache\""), "{log}");
    assert_eq!(count(&log, "experimental feature in use"), 0, "{log}");

    // The metrics.
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    for line in [
        "rdock_deprecated_config_in_use{element=\"routes.*.rule\"} 1",
        "rdock_deprecated_config_in_use{element=\"observability.alerts.webhook\"} 1",
        "rdock_experimental_feature_in_use{feature=\"wasm\"} 0",
        "rdock_experimental_feature_in_use{feature=\"http3\"} 0",
    ] {
        assert!(metrics.contains(line), "{line}\n{metrics}");
    }

    // The status document lists both, for the dashboard.
    let (status, body) = rdock.get_admin("/api/v1/status").unwrap();
    assert_eq!(status, 200, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    let deprecated = document["deprecations_in_use"].as_array().unwrap();
    let elements: Vec<&str> = deprecated
        .iter()
        .map(|d| d["element"].as_str().unwrap())
        .collect();
    assert_eq!(
        elements,
        ["observability.alerts.webhook", "routes.*.rule"],
        "{body}"
    );
    assert_eq!(deprecated[1]["paths"][0], "routes.app.rule");
    assert_eq!(deprecated[1]["removal"], "2.0");
    let beta: Vec<&str> = document["features_in_use"]["beta"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["feature"].as_str().unwrap())
        .collect();
    assert_eq!(beta, ["alerts", "http-cache"], "{body}");
    assert_eq!(
        document["features_in_use"]["experimental"],
        serde_json::json!([])
    );
    let warnings = document["last_reload"]["diagnostics"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|d| d["code"] == "deprecated" && d["path"] == "routes.app.rule"),
        "{body}"
    );

    // A deprecated API operation answers as before, with `Deprecation` and `Sunset`.
    let (status, head, _) = rdock
        .admin_send("GET", "/api/v1/listeners", &[], "")
        .unwrap();
    assert_eq!(status, 200);
    // 2026-11-14T00:00:00Z.
    assert_eq!(header(&head, "deprecation"), Some("@1794614400"), "{head}");
    assert_eq!(
        header(&head, "sunset"),
        Some("Sun, 14 Nov 2027 00:00:00 GMT"),
        "{head}"
    );
    let (_, head, _) = rdock.admin_send("GET", "/api/v1/status", &[], "").unwrap();
    assert_eq!(header(&head, "deprecation"), None);
    let (_, _, openapi) = rdock
        .admin_send("GET", "/api/openapi.json", &[], "")
        .unwrap();
    let openapi: serde_json::Value = serde_json::from_str(&openapi).unwrap();
    assert_eq!(
        openapi["paths"]["/api/v1/listeners"]["get"]["deprecated"],
        true
    );
    assert!(
        openapi["paths"]["/api/v1/status"]["get"]
            .get("deprecated")
            .is_none()
    );

    // Moved off: the gauges go back.
    rdock.write_config(&config(port, backend.addr, false));
    let (status, report) = rdock.reload();
    assert_eq!(status, 200, "{report}");
    let metrics = rdock.get_admin("/metrics").unwrap().1;
    assert!(
        !metrics.contains("rdock_deprecated_config_in_use{"),
        "{metrics}"
    );
    let reply = client::http1(proxy, get("app.test", "/")).await;
    assert_eq!(reply.status, 200);
    rdock.stop(std::time::Duration::from_secs(10));
}

#[test]
fn without_the_hook_the_test_entries_do_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    std::fs::write(
        &file,
        "routes:\n  app: { rule: \"Host(`a`)\", service: app }\nservices:\n  app: { backends: [{ address: \"127.0.0.1:1\" }] }\n",
    )
    .unwrap();
    let out = std::process::Command::new(RDOCK)
        .args(["validate", file.to_str().unwrap()])
        .env_remove("RDOCK_TEST_DEPRECATIONS")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("missing field `match`"), "{text}");
}

#[test]
fn the_hook_exercises_validate_schema_cli_and_migrate() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let text = "# keep me\nroutes:\n  app: { rule: \"Host(`a`)\", service: app }   # and me\nservices:\n  app: { backends: [{ address: \"127.0.0.1:1\" }] }\n";
    std::fs::write(&file, text).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(RDOCK)
            .args(args)
            .env("RDOCK_TEST_DEPRECATIONS", "1")
            .output()
            .unwrap()
    };
    // validate: a warning, an error under --strict and --deprecations=error.
    let out = run(&["validate", "--format", "json", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let d = report[0]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "deprecated")
        .unwrap()
        .clone();
    assert_eq!(d["severity"], "warning");
    assert_eq!(d["path"], "routes.app.rule");
    assert_eq!(d["element"], "routes.*.rule");
    assert_eq!(d["since"], "1.0");
    assert_eq!(d["removal"], "2.0");
    assert_eq!(d["replacement"], "`routes.<name>.match`");
    for flags in [&["--strict"][..], &["--deprecations", "error"][..]] {
        let mut args = vec!["validate"];
        args.extend_from_slice(flags);
        args.push(file.to_str().unwrap());
        assert_eq!(run(&args).status.code(), Some(1), "{flags:?}");
    }
    // The schema has the old key back, deprecated.
    let schema: serde_json::Value = serde_json::from_slice(&run(&["schema"]).stdout).unwrap();
    let pointer = rdock_model::locate(&schema, "routes.*.rule").unwrap();
    assert_eq!(
        schema.pointer(&format!("{pointer}/deprecated")),
        Some(&serde_json::Value::Bool(true))
    );
    // A deprecated flag warns on standard error and still works.
    let out = run(&["version", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "warning: `rdock version --json` is deprecated since 1.0 and will be removed in 2.0"
        ),
        "{stderr}"
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stdout).is_ok());
    assert_eq!(String::from_utf8_lossy(&run(&["version"]).stderr), "");
    // migrate config: the rename as a text edit, comments kept; --write keeps a backup.
    let out = run(&["migrate", "config", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        text.replace("rule:", "match:")
    );
    let out = run(&["migrate", "config", "--write", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        text.replace("rule:", "match:")
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("rdock.yaml.bak")).unwrap(),
        text
    );
}
