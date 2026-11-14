//! End-to-end tests of the `rdock` binary.

// Test helpers spawn the binary and decode its output; failing loudly is the point.
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

fn rdock(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(args)
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn validates_the_examples() {
    let output = rdock(&[
        "validate",
        "examples/config/rdock.full.yaml",
        "examples/config/rdock.minimal.json",
    ]);
    assert!(output.status.success(), "{}", stdout(&output));
    let text = stdout(&output);
    // Every setting of the full example is implemented, so it validates without warnings.
    assert!(
        text.contains("examples/config/rdock.full.yaml: valid\n"),
        "{text}"
    );
    let quickstart = rdock(&[
        "validate",
        "--strict",
        "examples/config/rdock.quickstart.yaml",
    ]);
    assert!(quickstart.status.success(), "{}", stdout(&quickstart));
    assert_eq!(
        stdout(&quickstart),
        "examples/config/rdock.quickstart.yaml: valid\n"
    );
}

#[test]
fn reports_errors_with_paths_and_hints() {
    let dir = std::env::temp_dir().join(format!("rdock-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("broken.yaml");
    std::fs::write(&file, "routes:\n  app:\n    match: \"Host(`a.example.com`)\"\n    service: ap\n    midlewares: []\nservices:\n  app:\n    backends: [{ address: \"app:3000\" }]\n").unwrap();
    let output = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(
        text.contains(
            "error: routes.app.midlewares: unknown key `midlewares`\n    did you mean `middlewares`?"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "error: routes.app.service: service `ap` does not exist\n    did you mean `app`?"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("broken.yaml: 2 errors, 0 warnings\n"),
        "{text}"
    );

    let json = rdock(&["validate", "--format", "json", file.to_str().unwrap()]);
    let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report[0]["errors"], 2);
    assert_eq!(report[0]["diagnostics"][1]["path"], "routes.app.service");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_files_are_errors() {
    let output = rdock(&["validate", "does-not-exist.yaml"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("cannot read does-not-exist.yaml"));
}

#[test]
fn private_names_go_to_the_local_ca_except_single_labels() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("local.yaml");
    std::fs::write(
        &file,
        "listeners:\n  websecure: { address: \":443\", tls: {} }\nroutes:\n  app:\n    match: \"Host(`app.localhost`) || Host(`nas`)\"\n    service: app\nservices:\n  app:\n    backends: [{ address: \"app:3000\" }]\n",
    )
    .unwrap();
    let output = rdock(&["validate", file.to_str().unwrap()]);
    let text = stdout(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("warning: routes.app.tls: no certificate authority, not even the local one, can certify the single-label name nas\n    use `nas.internal` or `nas.home.arpa`"),
        "{text}"
    );
    assert!(!text.contains("app.localhost"), "{text}");
}

#[test]
fn prints_the_committed_schema() {
    let output = rdock(&["schema"]);
    assert!(output.status.success());
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/rdock.v1.json"),
    )
    .unwrap();
    assert_eq!(stdout(&output), committed);
}

#[test]
fn prints_version_information() {
    let output = rdock(&["version", "--json"]);
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["rustc"].as_str().unwrap().starts_with("rustc "));
    let text = stdout(&rdock(&["--version"]));
    assert_eq!(text, format!("rdock {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn hash_prints_a_verifiable_argon2id_entry() {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(["hash", "--user", "alice"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"s3cret\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = stdout(&output);
    let hash = text.trim_end().strip_prefix("alice:").unwrap();
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    let parsed = PasswordHash::new(hash).unwrap();
    assert!(
        Argon2::default()
            .verify_password(b"s3cret", &parsed)
            .is_ok()
    );
    assert!(
        Argon2::default()
            .verify_password(b"s3cret\n", &parsed)
            .is_err()
    );

    let empty = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .arg("hash")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(2));
}

#[test]
fn the_stock_binary_registers_no_plugins_and_says_so() {
    let dir = std::env::temp_dir().join(format!("rdock-cli-plugins-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("plugins.yaml");
    std::fs::write(
        &file,
        "middlewares:\n  geo: { type: plugin, name: geo_block, config: { deny: [XX] } }\n  waf: { type: agent, address: \"http://waf.internal:8080\", protocol: spop }\n",
    )
    .unwrap();
    let output = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(
        text.contains("error: middlewares.geo.name: no plugin `geo_block`: this build of rdock registers no plugins\n    plugins are compiled into a custom binary"),
        "{text}"
    );
    assert!(
        text.contains(
            "warning: middlewares.waf.address: plain `http://` to a host that is not loopback"
        ),
        "{text}"
    );
    assert!(
        text.contains("warning: middlewares.waf.protocol: agents over HAProxy's SPOP (`spop`): not supported in this version (planned for a later version)"),
        "{text}"
    );
    std::fs::write(&file, "middlewares:\n  bad: { type: plugin, name: Geo }\n").unwrap();
    let text = stdout(&rdock(&["validate", file.to_str().unwrap()]));
    assert!(
        text.contains("error: middlewares.bad.name: `Geo` is not a plugin name"),
        "{text}"
    );
    let version = rdock(&["version", "--json"]);
    let info: serde_json::Value = serde_json::from_slice(&version.stdout).unwrap();
    assert_eq!(info["plugins"], serde_json::json!([]));
    assert_eq!(info["plugin_api"], "0.1.0");
    let wasm_abi = if cfg!(feature = "wasm") {
        serde_json::json!("0.1.0")
    } else {
        serde_json::Value::Null
    };
    assert_eq!(info["wasm_abi"], wasm_abi);
    assert_eq!(info["http3"], cfg!(feature = "http3"));
    let text = stdout(&rdock(&["version"]));
    let http3 = if cfg!(feature = "http3") {
        "HTTP/3: quinn and h3 (experimental)"
    } else {
        "HTTP/3: not in this build"
    };
    assert!(text.contains(http3), "{text}");
}

#[cfg(not(feature = "http3"))]
#[test]
fn http3_needs_the_opt_in_and_a_build_with_the_feature() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let config = "listeners:\n  websecure: { address: \":443\", tls: {}, http3: { enabled: true } }\n  web: { address: \":80\" }\n";
    std::fs::write(&file, config).unwrap();
    // Experimental (ADR-0033): refused without the opt-in, whatever the build.
    let out = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(
        text.contains("error: listeners.websecure.http3.enabled: the experimental feature `http3` (HTTP/3 over QUIC on `https` listeners) is used but not enabled"),
        "{text}"
    );
    assert!(text.contains("add `experimental: [http3]`"), "{text}");
    assert!(text.contains("`http3` cargo feature"), "{text}");
    // With it, the build is what is missing.
    std::fs::write(&file, format!("experimental: [http3]\n{config}")).unwrap();
    let out = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert!(
        text.contains("warning: listeners.websecure.http3.enabled: HTTP/3 (`http3.enabled`): this build does not include HTTP/3; build with --features http3"),
        "{text}"
    );
    assert!(!text.contains("experimental feature"), "{text}");
}

#[cfg(not(feature = "wasm"))]
#[test]
fn wasm_plugins_need_the_opt_in_and_a_build_with_the_feature() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let config = "middlewares:\n  w: { type: wasm, path: /plugins/p.wasm, sha256: \"0000000000000000000000000000000000000000000000000000000000000000\", trusted_keys: [\"RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\"] }\n";
    std::fs::write(&file, config).unwrap();
    let out = rdock(&["validate", "--format", "json", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let d = &report[0]["diagnostics"][0];
    assert_eq!(d["severity"], "error");
    assert_eq!(d["path"], "middlewares.w");
    assert_eq!(d["code"], "experimental_not_enabled");
    // `rdock run` refuses it for the same reason.
    let data = dir.path().join("data");
    let out = rdock(&[
        "run",
        "--config",
        file.to_str().unwrap(),
        "--data-dir",
        data.to_str().unwrap(),
        "--no-watch",
    ]);
    assert_ne!(out.status.code(), Some(0));
    let text = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("experimental feature `wasm`"), "{text}");
    // With the opt-in, the build is what is missing: a warning here, refused by `rdock run`.
    std::fs::write(&file, format!("experimental: [wasm]\n{config}")).unwrap();
    let text = stdout(&rdock(&["validate", file.to_str().unwrap()]));
    assert!(
        text.contains("warning: middlewares.w: WASM plugins (`type: wasm`): this build does not include WASM plugins; build with --features wasm"),
        "{text}"
    );
    let out = rdock(&[
        "run",
        "--config",
        file.to_str().unwrap(),
        "--data-dir",
        data.to_str().unwrap(),
        "--no-watch",
    ]);
    assert_ne!(out.status.code(), Some(0));
    let text = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert!(
        text.contains("this build does not include WASM plugins"),
        "{text}"
    );
}

/// `tests/migrate-config/<name>.yaml` migrates to `<name>.migrated.yaml`, comments kept, and
/// the result validates without deprecation warnings (ADR-0033).
#[test]
fn migrate_config_matches_the_golden_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/migrate-config");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name.contains(".migrated.") || path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let golden = dir.join(name.replace(".yaml", ".migrated.yaml"));
        let out = rdock(&["migrate", "config", path.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{name}");
        assert_eq!(
            stdout(&out),
            std::fs::read_to_string(&golden).unwrap(),
            "{name}: run `rdock migrate config {name}` and compare"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("rewrote observability.alerts.webhook"),
            "{stderr}"
        );
        let out = rdock(&["validate", "--format", "json", golden.to_str().unwrap()]);
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            report[0]["diagnostics"]
                .as_array()
                .unwrap()
                .iter()
                .all(|d| d["code"] != "deprecated"),
            "{report}"
        );
        // The original validates with the deprecation warning only (and passes without --strict).
        let out = rdock(&["validate", "--format", "json", path.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0));
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let deprecated: Vec<&serde_json::Value> = report[0]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["code"] == "deprecated")
            .collect();
        assert_eq!(deprecated.len(), 1, "{report}");
        assert_eq!(deprecated[0]["element"], "observability.alerts.webhook");
        assert_eq!(deprecated[0]["since"], "1.0");
        assert_eq!(deprecated[0]["removal"], "2.0");
        assert!(
            deprecated[0]["replacement"]
                .as_str()
                .unwrap()
                .contains("channels")
        );
        checked += 1;
    }
    assert!(checked > 0);
}

#[test]
fn migrate_config_diffs_reads_stdin_and_refuses_unknown_versions() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/migrate-config/alerts-webhook.yaml");
    let out = rdock(&["migrate", "config", "--diff", golden.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let diff = stdout(&out);
    assert!(
        diff.contains("+++ ") && diff.contains("(migrated)"),
        "{diff}"
    );
    assert!(
        diff.contains("-    webhook:") && diff.contains("+    channels:"),
        "{diff}"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(["migrate", "config", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"version: 2\n").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("reads configuration schema version 1 only"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dir = tempfile::tempdir().unwrap();
    let clean = dir.path().join("rdock.yaml");
    std::fs::write(&clean, "routes: {}\n").unwrap();
    let out = rdock(&["migrate", "config", "--write", clean.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing to migrate"));
    assert!(
        !dir.path().join("rdock.yaml.bak").exists(),
        "no backup when nothing changes"
    );
    let out = rdock(&["migrate", "config", "--write", "-"]);
    assert_eq!(out.status.code(), Some(2));
}

/// One source for maturity (ADR-0033): `rdock version --json` lists the registry, and the
/// website's planned settings (`apps/website/src/data/status.json`) never contradict it.
#[test]
fn version_lists_the_maturity_registry_and_status_json_agrees_with_it() {
    use rdock_model::maturity::{FEATURES, Level, covering, listed};
    let info: serde_json::Value =
        serde_json::from_str(&stdout(&rdock(&["version", "--json"]))).unwrap();
    let features = info["features"].as_array().unwrap();
    assert_eq!(features.len(), FEATURES.len());
    let wasm = features.iter().find(|f| f["id"] == "wasm").unwrap();
    assert_eq!(wasm["level"], "experimental");
    assert_eq!(wasm["cargo_feature"], "wasm");
    assert_eq!(wasm["built"], cfg!(feature = "wasm"));
    assert_eq!(info["schema_version"], 1);
    let text = stdout(&rdock(&["version"]));
    assert!(text.contains("\nexperimental: wasm"), "{text}");
    assert!(text.contains("\nbeta: "), "{text}");

    let status =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/website/src/data/status.json");
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(status).unwrap()).unwrap();
    for entry in entries {
        let path = entry["path"].as_str().unwrap().replace("<name>", "*");
        // Every planned setting lies in a known feature area…
        assert!(covering(&path).is_some(), "{path} is in no feature area");
        // …is never itself declared as shipped and stable…
        assert!(
            listed(&path).is_none_or(|f| f.level != Level::Stable),
            "{path} is planned, yet listed as stable"
        );
        // …and its fixture names the experimental features it uses.
        let fixture = entry["fixture"].as_str().unwrap();
        let loaded = rdock_config::load_str(fixture, rdock_config::Format::Yaml).unwrap();
        let refused: Vec<&rdock_model::Diagnostic> = loaded
            .diagnostics
            .iter()
            .filter(|d| {
                d.code
                    .as_deref()
                    .is_some_and(|c| c.starts_with("experimental_"))
            })
            .collect();
        assert_eq!(refused, Vec::<&rdock_model::Diagnostic>::new(), "{path}");
    }
}

/// In a build with HTTP/3, the opt-in is what is required, and it is enough (ADR-0033).
#[cfg(feature = "http3")]
#[test]
fn with_the_http3_build_the_opt_in_is_required_and_enough() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let config = "listeners:\n  websecure: { address: \":443\", tls: {}, http3: { enabled: true } }\n  web: { address: \":80\" }\n";
    std::fs::write(&file, config).unwrap();
    let out = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("the experimental feature `http3`"));
    std::fs::write(&file, format!("experimental: [http3]\n{config}")).unwrap();
    let out = rdock(&["validate", "--strict", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

/// In a build with WASM plugins, the opt-in is what is required, and it is enough (ADR-0033).
#[cfg(feature = "wasm")]
#[test]
fn with_the_wasm_build_the_opt_in_is_required_and_enough() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rdock.yaml");
    let config = "middlewares:\n  w: { type: wasm, path: /plugins/p.wasm, sha256: \"0000000000000000000000000000000000000000000000000000000000000000\", trusted_keys: [\"RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\"] }\n";
    std::fs::write(&file, config).unwrap();
    let out = rdock(&["validate", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("the experimental feature `wasm`"));
    // With it, validation goes on to load the module (which this test does not provide).
    std::fs::write(&file, format!("experimental: [wasm]\n{config}")).unwrap();
    let text = stdout(&rdock(&["validate", file.to_str().unwrap()]));
    assert!(!text.contains("experimental feature"), "{text}");
    assert!(!text.contains("this build does not include"), "{text}");
    assert!(
        text.contains("middlewares.w.path: cannot read /plugins/p.wasm"),
        "{text}"
    );
}

/// `rdock migrate traefik` (ADR-0033): the YAML on standard output, the report as JSON with
/// `--report`, exit 1 for an input it does not read, 2 with `--strict` when something is
/// manual or dropped; `${VAR}` values come from `--env-file`, and from the process
/// environment only with `--process-env`.
#[test]
fn migrate_traefik_reports_and_exits_as_documented() {
    let dir = tempfile::tempdir().unwrap();
    let compose = dir.path().join("compose.yaml");
    std::fs::write(
        &compose,
        "services:\n  app:\n    image: traefik/whoami\n    expose: [80]\n    labels:\n      traefik.enable: 'true'\n      traefik.http.routers.app.rule: Host(`${DOMAIN}`)\n      traefik.http.routers.app.entrypoints: websecure\n      traefik.http.routers.app.tls: 'true'\n",
    )
    .unwrap();
    let env = dir.path().join("vars.env");
    std::fs::write(&env, "DOMAIN=app.example.com\n").unwrap();
    let report = dir.path().join("report.json");
    let path = compose.to_str().unwrap();
    // The variable is set in this process's environment, but not read without --process-env.
    let out = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(["migrate", "traefik", path, "--strict"])
        .env("DOMAIN", "from-the-environment.example.com")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!stdout(&out).contains("from-the-environment"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("compose.interpolation.unset"));
    let out = Command::new(env!("CARGO_BIN_EXE_rdock"))
        .args(["migrate", "traefik", path, "--process-env"])
        .env("DOMAIN", "from-the-environment.example.com")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stdout(&out).contains("Host(`from-the-environment.example.com`)"));
    // --env-file and --report.
    let out = rdock(&[
        "migrate",
        "traefik",
        path,
        "--env-file",
        env.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--strict",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stdout(&out).contains("Host(`app.example.com`)"));
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["summary"]["items"], 5);
    assert_eq!(json["summary"]["manual"], 0);
    // Not a Compose file or Traefik configuration: 1. A missing file: 2.
    std::fs::write(&compose, "foo: 1\n").unwrap();
    assert_eq!(rdock(&["migrate", "traefik", path]).status.code(), Some(1));
    let missing = dir.path().join("missing.yaml");
    assert_eq!(
        rdock(&["migrate", "traefik", missing.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
}

/// `rdock migrate caddy` (ADR-0033): adapted JSON in, a Caddyfile refused with exit 1 and how to
/// adapt it, `--strict` exits 2 when something is manual, `--full` writes listeners.
#[test]
fn migrate_caddy_reports_and_exits_as_documented() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("caddy.json");
    std::fs::write(
        &json,
        r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"subroute","routes":[{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"app:8080"}]}]}]}],"terminal":true}]}}}}}"#,
    )
    .unwrap();
    let path = json.to_str().unwrap();
    let report = dir.path().join("report.json");
    let out = rdock(&[
        "migrate",
        "caddy",
        path,
        "--full",
        "--strict",
        "--report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stdout(&out).contains("Host(`app.example.com`)"));
    assert!(stdout(&out).contains("websecure"));
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(parsed["source"]["kind"], "caddy");
    let caddyfile = dir.path().join("Caddyfile");
    std::fs::write(
        &caddyfile,
        "app.example.com {\n\treverse_proxy app:8080\n}\n",
    )
    .unwrap();
    let out = rdock(&["migrate", "caddy", caddyfile.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("caddy adapt"));
    std::fs::write(
        &json,
        r#"{"apps":{"http":{"servers":{"srv0":{"listen":[":80"],"routes":[{"handle":[{"handler":"templates"},{"handler":"static_response","status_code":200}]}]}}}}}"#,
    )
    .unwrap();
    assert_eq!(
        rdock(&["migrate", "caddy", path, "--strict"]).status.code(),
        Some(2)
    );
}

/// `rdock migrate nginx` (ADR-0033, beta): includes resolved against the file's directory,
/// exit 1 for something that is not an NGINX configuration, 2 with `--strict` when a construct
/// is refused.
#[test]
fn migrate_nginx_reports_and_exits_as_documented() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("conf.d")).unwrap();
    std::fs::write(
        dir.path().join("conf.d/site.conf"),
        "server { listen 80; server_name app.example.com; location / { proxy_pass http://app:8080; } }\n",
    )
    .unwrap();
    let conf = dir.path().join("nginx.conf");
    std::fs::write(&conf, "http { include conf.d/*.conf; }\n").unwrap();
    let path = conf.to_str().unwrap();
    let out = rdock(&["migrate", "nginx", path, "--strict"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(stdout(&out).contains("Host(`app.example.com`)"));
    std::fs::write(&conf, "http { server { listen 80; location / { if ($x) { return 403; } proxy_pass http://a:80; } } }\n").unwrap();
    let out = rdock(&["migrate", "nginx", path, "--strict"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("nginx.refused"));
    std::fs::write(&conf, "{\"apps\": {}}\n").unwrap();
    assert_eq!(rdock(&["migrate", "nginx", path]).status.code(), Some(1));
}

/// `rdock schema --migrate-report` prints the committed report schema.
#[test]
fn the_migrate_report_schema_is_printed() {
    let out = rdock(&["schema", "--migrate-report"]);
    assert!(out.status.success());
    let committed = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/migrate-report.v1.json"),
    )
    .unwrap();
    assert_eq!(stdout(&out), committed);
}
