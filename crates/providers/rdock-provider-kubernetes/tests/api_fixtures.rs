//! Every Gateway API document of a kind we model in the upstream conformance manifests
//! (v1.7.0, `tests/fixtures/upstream`) deserialises into our types, and survives a round trip.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use rdock_provider_kubernetes::api::{
    BackendTLSPolicy, GRPCRoute, Gateway, GatewayClass, HTTPRoute, ListenerSet, ReferenceGrant,
    TCPRoute, TLSRoute, UDPRoute,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Deserialises `doc` as `T`, serialises it again and checks that the result reads back the
/// same.
fn check<T: DeserializeOwned + Serialize + PartialEq + std::fmt::Debug>(doc: &Value, at: &str) {
    let typed: T =
        serde_json::from_value(doc.clone()).unwrap_or_else(|e| panic!("{at}: {e}\n{doc:#}"));
    let again: T = serde_json::from_value(serde_json::to_value(&typed).unwrap())
        .unwrap_or_else(|e| panic!("{at}: round trip: {e}"));
    assert_eq!(typed, again, "{at}: round trip");
}

#[test]
fn upstream_conformance_manifests_deserialise() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    assert!(files.len() > 100, "{} fixture files", files.len());
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let docs: Vec<Value> = serde_saphyr::from_multiple(&text)
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for (i, doc) in docs.iter().enumerate() {
            if doc.is_null() || doc["apiVersion"] != "gateway.networking.k8s.io/v1" {
                continue;
            }
            let kind = doc["kind"].as_str().unwrap_or_default().to_owned();
            let at = format!("{}#{i} ({kind})", file.display());
            match kind.as_str() {
                "GatewayClass" => check::<GatewayClass>(doc, &at),
                "Gateway" => check::<Gateway>(doc, &at),
                "HTTPRoute" => check::<HTTPRoute>(doc, &at),
                "GRPCRoute" => check::<GRPCRoute>(doc, &at),
                "TLSRoute" => check::<TLSRoute>(doc, &at),
                "TCPRoute" => check::<TCPRoute>(doc, &at),
                "UDPRoute" => check::<UDPRoute>(doc, &at),
                "ReferenceGrant" => check::<ReferenceGrant>(doc, &at),
                "ListenerSet" => check::<ListenerSet>(doc, &at),
                "BackendTLSPolicy" => check::<BackendTLSPolicy>(doc, &at),
                other => panic!("{at}: a v1 kind we do not model: {other}"),
            }
            *seen.entry(kind).or_default() += 1;
        }
    }
    for kind in [
        "GatewayClass",
        "Gateway",
        "HTTPRoute",
        "GRPCRoute",
        "TLSRoute",
        "TCPRoute",
        "UDPRoute",
        "ReferenceGrant",
        "ListenerSet",
        "BackendTLSPolicy",
    ] {
        assert!(
            seen.get(kind).copied().unwrap_or(0) > 0,
            "no {kind} in the fixtures: {seen:?}"
        );
    }
}

#[test]
fn fields_are_read_from_upstream_yaml() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream");
    let text = std::fs::read_to_string(dir.join("httproute-redirect-path.yaml")).unwrap();
    let route: HTTPRoute = serde_saphyr::from_str(&text).unwrap();
    assert_eq!(route.spec.parent_refs[0].name, "same-namespace");
    let rule = &route.spec.rules[0];
    let path = rule.matches[0].path.as_ref().unwrap();
    assert_eq!(path.kind.as_deref(), Some("PathPrefix"));
    assert_eq!(path.value.as_deref(), Some("/original-prefix"));
    let redirect = rule.filters[0].request_redirect.as_ref().unwrap();
    let modifier = redirect.path.as_ref().unwrap();
    assert_eq!(modifier.kind, "ReplacePrefixMatch");
    assert_eq!(
        modifier.replace_prefix_match.as_deref(),
        Some("/replacement-prefix")
    );
    assert_eq!(
        route.spec.rules[3].filters[0]
            .request_redirect
            .as_ref()
            .unwrap()
            .status_code,
        Some(301)
    );

    let base = std::fs::read_to_string(dir.join("base-manifests.yaml")).unwrap();
    let docs: Vec<Value> = serde_saphyr::from_multiple(&base).unwrap();
    let gateway: Gateway = docs
        .iter()
        .filter(|d| d["kind"] == "Gateway")
        .map(|d| serde_json::from_value(d.clone()).unwrap())
        .find(|g: &Gateway| g.metadata.name.as_deref() == Some("backend-namespaces"))
        .unwrap();
    let listener = &gateway.spec.listeners[0];
    assert_eq!((listener.port, listener.protocol.as_str()), (80, "HTTP"));
    let namespaces = listener
        .allowed_routes
        .as_ref()
        .unwrap()
        .namespaces
        .as_ref()
        .unwrap();
    assert_eq!(namespaces.from.as_deref(), Some("Selector"));
    assert!(namespaces.selector.is_some());
}

#[test]
fn unknown_fields_and_values_do_not_fail_an_object() {
    let doc = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "n" },
        "spec": {
            "parentRefs": [{ "name": "gw", "futureField": true }],
            "rules": [{
                "matches": [{ "path": { "type": "SomeFutureMatch", "value": "/x" } }],
                "filters": [{ "type": "FutureFilter", "futureFilter": { "a": 1 } }],
                "backendRefs": [{ "name": "svc", "port": 80, "weight": 0 }],
                "newRuleField": "x"
            }]
        },
        "status": { "parents": [{ "parentRef": { "name": "gw" }, "controllerName": "x/y", "conditions": [] }] }
    });
    let route: HTTPRoute = serde_json::from_value(doc).unwrap();
    let rule = &route.spec.rules[0];
    assert_eq!(
        rule.matches[0].path.as_ref().unwrap().kind.as_deref(),
        Some("SomeFutureMatch")
    );
    assert_eq!(rule.filters[0].kind, "FutureFilter");
    assert_eq!(rule.backend_refs[0].backend.reference.name, "svc");
    assert_eq!(rule.backend_refs[0].backend.weight, Some(0));
    assert_eq!(route.status.unwrap().parents[0].controller_name, "x/y");
}
