//! The adapter against a fake Hetzner Cloud API that keeps record sets and runs actions like the
//! real one. Requests are checked against the OpenAPI document
//! <https://docs.hetzner.cloud/cloud.spec.json> (2026-11-07): `GET /zones/{id_or_name}`,
//! `POST /zones/{id_or_name}/rrsets/{rr_name}/{rr_type}/actions/add_records` with
//! `{ttl, records: [{value}]}`, `…/remove_records` with `{records: [{value}]}`, both answering
//! `201 {action}`, and `GET /actions/{id}`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Params, Recorded, Reply};

use super::*;

#[derive(Default)]
struct Zone {
    token: String,
    /// TXT record sets of `example.com` by relative name, values as sent (quoted).
    rrsets: BTreeMap<String, Vec<String>>,
    next_action: u64,
}

impl Zone {
    fn action(&mut self, command: &str) -> Reply {
        self.next_action += 1;
        Reply::json(
            201,
            json!({ "action": { "id": self.next_action, "command": command, "status": "running", "progress": 0, "error": null } }),
        )
    }
}

fn error(status: u16, code: &str, message: &str) -> Reply {
    Reply::json(
        status,
        json!({ "error": { "code": code, "message": message } }),
    )
}

fn values(request: &Recorded) -> Vec<String> {
    request.json()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["value"].as_str().unwrap().to_owned())
        .collect()
}

/// One zone, `example.com`.
struct HetznerFake {
    api: FakeApi,
    zone: Arc<Mutex<Zone>>,
}

impl HetznerFake {
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let zone: Arc<Mutex<Zone>> = Arc::default();
        let state = zone.clone();
        api.guard(move |request| {
            let expected = format!("Bearer {}", state.lock().unwrap().token);
            (request.header("authorization") != Some(expected.as_str()))
                .then(|| error(401, "unauthorized", "unable to authenticate"))
        });
        api.route("GET", "/zones/{zone}", |_, params| {
            if params["zone"] == "example.com" {
                Reply::json(
                    200,
                    json!({ "zone": { "id": 42, "name": "example.com", "mode": "primary" } }),
                )
            } else {
                error(404, "not_found", "zone not found")
            }
        });
        let state = zone.clone();
        api.route(
            "POST",
            "/zones/{zone}/rrsets/{name}/{type}/actions/add_records",
            move |request, params| {
                if let Some(refused) = check_rrset(params) {
                    return refused;
                }
                assert_eq!(request.json()["ttl"], 60);
                let mut zone = state.lock().unwrap();
                let rrset = zone.rrsets.entry(params["name"].clone()).or_default();
                for value in values(request) {
                    assert!(value.starts_with('"') && value.ends_with('"'), "{value}");
                    if !rrset.contains(&value) {
                        rrset.push(value);
                    }
                }
                zone.action("add_rrset_records")
            },
        );
        let state = zone.clone();
        api.route(
            "POST",
            "/zones/{zone}/rrsets/{name}/{type}/actions/remove_records",
            move |request, params| {
                if let Some(refused) = check_rrset(params) {
                    return refused;
                }
                let mut zone = state.lock().unwrap();
                let Some(rrset) = zone.rrsets.get_mut(&params["name"]) else {
                    return error(404, "not_found", "rrset not found");
                };
                let removed = values(request);
                rrset.retain(|value| !removed.contains(value));
                if rrset.is_empty() {
                    zone.rrsets.remove(&params["name"]);
                }
                zone.action("remove_rrset_records")
            },
        );
        api.route("GET", "/actions/{id}", |_, params| {
            let id: u64 = params["id"].parse().unwrap();
            Reply::json(200, json!({ "action": { "id": id, "status": "success", "progress": 100, "error": null } }))
        });
        Self { api, zone }
    }

    fn solver(&self, token: &str, zone: Option<&str>) -> HetznerDns {
        HetznerDns::new(&HetznerProvider {
            api_token: token.to_owned(),
            zone: zone.map(str::to_owned),
            api_url: Some(self.api.url().parse().unwrap()),
        })
        .unwrap()
    }
}

/// The zone must be `example.com` and the type TXT.
fn check_rrset(params: &Params) -> Option<Reply> {
    if !matches!(params["zone"].as_str(), "example.com") {
        return Some(error(404, "not_found", "zone not found"));
    }
    assert_eq!(params["type"], "TXT");
    assert_eq!(
        params["name"],
        params["name"].to_lowercase(),
        "names are lower case"
    );
    None
}

impl ContractFake for HetznerFake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let relative = fqdn.strip_suffix(".example.com").unwrap();
        let zone = self.zone.lock().unwrap();
        zone.rrsets
            .get(relative)
            .into_iter()
            .flatten()
            .map(|value| value.trim_matches('"').to_owned())
            .collect()
    }

    fn accept_only(&self, credential: &str) {
        credential.clone_into(&mut self.zone.lock().unwrap().token);
    }

    fn fail_next_write(&self) {
        let reset = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1;
        self.api.fail(
            "POST",
            "/zones/{zone}/rrsets/{name}/{type}/actions/add_records",
            1,
            error(
                429,
                "rate_limit_exceeded",
                "limit of 3600 requests per hour reached",
            )
            .header("RateLimit-Reset", &reset.to_string()),
        );
    }
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = HetznerFake::start().await;
    dns_contract::run(&fake, ["first-token", "second-token"], |token| {
        Arc::new(fake.solver(token, None))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = HetznerFake::start().await;
    fake.accept_only("token");
    let dns = fake.solver("token", None);
    dns.present("_acme-challenge.APP.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let requests = fake.api.requests();
    let lines = fake.api.lines();
    assert_eq!(
        lines,
        [
            "GET /zones/_acme-challenge.app.example.com",
            "GET /zones/app.example.com",
            "GET /zones/example.com",
            "POST /zones/example.com/rrsets/_acme-challenge.app/TXT/actions/add_records",
            "GET /actions/1",
            "POST /zones/example.com/rrsets/_acme-challenge.app/TXT/actions/remove_records",
            "GET /actions/2",
        ]
    );
    assert_eq!(
        requests[3].json(),
        json!({ "ttl": 60, "records": [{ "value": "\"v4lue\"" }] })
    );
    assert_eq!(
        requests[5].json(),
        json!({ "records": [{ "value": "\"v4lue\"" }] })
    );
    assert_eq!(requests[3].header("authorization"), Some("Bearer token"));
    assert_eq!(requests[3].header("content-type"), Some("application/json"));
}

#[tokio::test]
async fn reports_failed_actions_and_api_errors() {
    let fake = HetznerFake::start().await;
    fake.accept_only("token");
    fake.api.fail(
        "POST",
        "/zones/{zone}/rrsets/{name}/{type}/actions/add_records",
        1,
        Reply::json(
            201,
            json!({ "action": { "id": 9, "status": "error", "error": { "code": "protected", "message": "rrset is protected" } } }),
        ),
    );
    let dns = fake.solver("token", Some("example.com"));
    let failed = dns
        .present("_acme-challenge.example.com", "x")
        .await
        .unwrap_err();
    assert_eq!(
        failed.0,
        "Hetzner Cloud API action 9 failed: rrset is protected (protected)"
    );
    let unauthorized = fake
        .solver("wrong", Some("example.com"))
        .present("_acme-challenge.example.com", "x")
        .await
        .unwrap_err();
    assert!(
        unauthorized
            .0
            .contains("401 Unauthorized: unable to authenticate (unauthorized)"),
        "{unauthorized}"
    );
}

#[tokio::test]
async fn removing_from_a_missing_rrset_is_done() {
    let fake = HetznerFake::start().await;
    fake.accept_only("token");
    fake.solver("token", Some("example.com"))
        .cleanup("_acme-challenge.example.com", "gone")
        .await
        .unwrap();
}
