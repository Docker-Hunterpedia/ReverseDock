//! The adapter against a fake DigitalOcean API that keeps records like the real one.
//! Requests are checked against the API reference:
//! <https://docs.digitalocean.com/reference/api/digitalocean/#tag/Domain-Records> (2026-11-07).

use std::sync::{Arc, Mutex};

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Reply};

use super::*;

#[derive(Default)]
struct Records {
    token: String,
    next_id: u64,
    /// (id, name relative to `example.com`, data)
    txt: Vec<(u64, String, String)>,
}

fn full_name(relative: &str) -> String {
    if relative == "@" {
        "example.com".to_owned()
    } else {
        format!("{relative}.example.com")
    }
}

fn not_found() -> Reply {
    Reply::json(
        404,
        json!({ "id": "not_found", "message": "The resource you were accessing could not be found." }),
    )
}

/// One domain, `example.com`.
struct DigitalOceanFake {
    api: FakeApi,
    records: Arc<Mutex<Records>>,
}

impl DigitalOceanFake {
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let records: Arc<Mutex<Records>> = Arc::default();
        let state = records.clone();
        api.guard(move |request| {
            let expected = format!("Bearer {}", state.lock().unwrap().token);
            (request.header("authorization") != Some(expected.as_str())).then(|| {
                Reply::json(
                    401,
                    json!({ "id": "unauthorized", "message": "Unable to authenticate you" }),
                )
            })
        });
        api.route("GET", "/v2/domains/{name}", |_, params| {
            if params["name"] == "example.com" {
                Reply::json(
                    200,
                    json!({ "domain": { "name": "example.com", "ttl": 1800 } }),
                )
            } else {
                not_found()
            }
        });
        let state = records.clone();
        api.route("POST", "/v2/domains/{zone}/records", move |request, params| {
            if params["zone"] != "example.com" {
                return not_found();
            }
            let body = request.json();
            assert_eq!(body["type"], "TXT");
            let mut records = state.lock().unwrap();
            records.next_id += 1;
            let id = records.next_id;
            let (name, data) = (body["name"].as_str().unwrap(), body["data"].as_str().unwrap());
            records.txt.push((id, name.to_owned(), data.to_owned()));
            Reply::json(
                201,
                json!({ "domain_record": { "id": id, "type": "TXT", "name": name, "data": data, "ttl": body["ttl"] } }),
            )
        });
        let state = records.clone();
        api.route("GET", "/v2/domains/{zone}/records", move |request, _| {
            let name = request.query_param("name").unwrap();
            assert_eq!(request.query_param("type").as_deref(), Some("TXT"));
            let records: Vec<Value> = state
                .lock()
                .unwrap()
                .txt
                .iter()
                .filter(|(_, relative, _)| full_name(relative) == name)
                .map(|(id, relative, data)| {
                    json!({ "id": id, "type": "TXT", "name": relative, "data": data, "ttl": 30 })
                })
                .collect();
            let total = records.len();
            Reply::json(
                200,
                json!({ "domain_records": records, "links": {}, "meta": { "total": total } }),
            )
        });
        let state = records.clone();
        api.route(
            "DELETE",
            "/v2/domains/{zone}/records/{id}",
            move |_, params| {
                let id: u64 = params["id"].parse().unwrap();
                let mut records = state.lock().unwrap();
                let before = records.txt.len();
                records.txt.retain(|(have, _, _)| *have != id);
                if records.txt.len() == before {
                    not_found()
                } else {
                    Reply::status(204)
                }
            },
        );
        Self { api, records }
    }

    fn solver(&self, token: &str, zone: Option<&str>) -> DigitalOceanDns {
        DigitalOceanDns::new(&DigitalOceanProvider {
            api_token: token.to_owned(),
            zone: zone.map(str::to_owned),
            api_url: Some(self.api.url().parse().unwrap()),
        })
        .unwrap()
    }
}

impl ContractFake for DigitalOceanFake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let records = self.records.lock().unwrap();
        records
            .txt
            .iter()
            .filter(|(_, relative, _)| full_name(relative) == fqdn)
            .map(|(_, _, data)| data.clone())
            .collect()
    }

    fn accept_only(&self, credential: &str) {
        credential.clone_into(&mut self.records.lock().unwrap().token);
    }

    fn fail_next_write(&self) {
        self.api.fail(
            "POST",
            "/v2/domains/{zone}/records",
            1,
            Reply::too_many_requests(1),
        );
    }
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = DigitalOceanFake::start().await;
    dns_contract::run(&fake, ["dop_v1_first", "dop_v1_second"], |token| {
        Arc::new(fake.solver(token, None))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = DigitalOceanFake::start().await;
    fake.accept_only("dop_v1_token");
    let dns = fake.solver("dop_v1_token", None);
    dns.present("_acme-challenge.App.example.com.", "v4lue")
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
            "GET /v2/domains/_acme-challenge.app.example.com",
            "GET /v2/domains/app.example.com",
            "GET /v2/domains/example.com",
            "POST /v2/domains/example.com/records",
            "GET /v2/domains/example.com/records?type=TXT&name=_acme-challenge.app.example.com&per_page=200",
            "DELETE /v2/domains/example.com/records/1",
        ],
        "the zone is looked up once per solver"
    );
    let create = &requests[3];
    assert_eq!(
        create.json(),
        json!({ "type": "TXT", "name": "_acme-challenge.app", "data": "v4lue", "ttl": 30 })
    );
    assert_eq!(create.header("authorization"), Some("Bearer dop_v1_token"));
    assert_eq!(create.header("content-type"), Some("application/json"));
}

#[tokio::test]
async fn uses_the_configured_zone_and_reports_api_errors() {
    let fake = DigitalOceanFake::start().await;
    fake.accept_only("right");
    fake.solver("right", Some("example.com"))
        .present("_acme-challenge.example.com", "x")
        .await
        .unwrap();
    assert_eq!(fake.api.lines(), ["POST /v2/domains/example.com/records"]);
    assert_eq!(fake.txt_values("_acme-challenge.example.com"), ["x"]);
    let error = fake
        .solver("wrong", Some("example.com"))
        .present("_acme-challenge.example.com", "x")
        .await
        .unwrap_err();
    assert!(
        error
            .0
            .contains("401 Unauthorized: Unable to authenticate you (unauthorized)"),
        "{error}"
    );
    assert!(
        !error.0.contains("wrong"),
        "the token never appears in errors"
    );
}

#[tokio::test]
async fn reports_names_outside_every_domain() {
    let fake = DigitalOceanFake::start().await;
    fake.accept_only("t");
    let error = fake
        .solver("t", None)
        .present("_acme-challenge.example.org", "x")
        .await
        .unwrap_err();
    assert!(error.0.contains("no DigitalOcean zone holds"), "{error}");
}
