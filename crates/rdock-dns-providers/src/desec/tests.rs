//! The adapter against a fake deSEC API that keeps RRsets like the real one. Requests are
//! checked against <https://desec.readthedocs.io/en/latest/dns/rrsets.html> and
//! <https://desec.readthedocs.io/en/latest/dns/domains.html> (2026-11-07):
//! `GET /domains/?owns_qname=`, `GET /domains/{name}/`, `GET|PATCH
//! /domains/{name}/rrsets/{subname}/{type}/`, `POST /domains/{name}/rrsets/` with
//! `{subname, type, ttl, records}`, `Authorization: Token …`, TXT contents in double quotes,
//! and `records: []` deleting the RRset with `204`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Recorded, Reply};

use super::*;

#[derive(Default)]
struct Domain {
    token: String,
    /// TXT RRsets of `example.com` by subname, records as stored (quoted).
    rrsets: BTreeMap<String, Vec<String>>,
}

fn detail(status: u16, detail: &str) -> Reply {
    Reply::json(status, json!({ "detail": detail }))
}

fn records(request: &Recorded) -> Vec<String> {
    request.json()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            let record = record.as_str().unwrap();
            assert!(
                record.starts_with('"') && record.ends_with('"'),
                "TXT contents are quoted: {record}"
            );
            record.to_owned()
        })
        .collect()
}

/// One domain, `example.com`, with `minimum_ttl` 3600.
struct DesecFake {
    api: FakeApi,
    domain: Arc<Mutex<Domain>>,
}

impl DesecFake {
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let domain: Arc<Mutex<Domain>> = Arc::default();
        let state = domain.clone();
        api.guard(move |request| {
            assert!(request.path.ends_with('/'), "deSEC paths end with a slash");
            let expected = format!("Token {}", state.lock().unwrap().token);
            (request.header("authorization") != Some(expected.as_str()))
                .then(|| detail(401, "Invalid token."))
        });
        api.route("GET", "/domains", |request, _| {
            let qname = request.query_param("owns_qname").unwrap();
            let owned = qname == "example.com" || qname.ends_with(".example.com");
            Reply::json(
                200,
                if owned {
                    json!([{ "name": "example.com", "minimum_ttl": 3600 }])
                } else {
                    json!([])
                },
            )
        });
        api.route("GET", "/domains/{name}", |_, params| {
            if params["name"] == "example.com" {
                Reply::json(200, json!({ "name": "example.com", "minimum_ttl": 3600 }))
            } else {
                detail(404, "Not found.")
            }
        });
        let state = domain.clone();
        api.route(
            "GET",
            "/domains/{name}/rrsets/{subname}/{type}",
            move |_, params| {
                let domain = state.lock().unwrap();
                match domain.rrsets.get(&params["subname"]) {
                    Some(records) if params["name"] == "example.com" => Reply::json(
                        200,
                        json!({ "subname": params["subname"], "type": "TXT", "ttl": 3600, "records": records }),
                    ),
                    _ => detail(404, "Not found."),
                }
            },
        );
        let state = domain.clone();
        api.route("POST", "/domains/{name}/rrsets", move |request, params| {
            if params["name"] != "example.com" {
                return detail(404, "Not found.");
            }
            let body = request.json();
            assert_eq!(body["type"], "TXT");
            assert_eq!(body["ttl"], 3600, "the domain's minimum TTL");
            let subname = body["subname"].as_str().unwrap().to_owned();
            let mut domain = state.lock().unwrap();
            if domain.rrsets.contains_key(&subname) {
                return Reply::json(
                    400,
                    json!({ "non_field_errors": ["Another RRset with the same subdomain and type exists for this domain."] }),
                );
            }
            domain.rrsets.insert(subname, records(request));
            Reply::json(201, body)
        });
        let state = domain.clone();
        api.route(
            "PATCH",
            "/domains/{name}/rrsets/{subname}/{type}",
            move |request, params| {
                let mut domain = state.lock().unwrap();
                if params["name"] != "example.com"
                    || !domain.rrsets.contains_key(&params["subname"])
                {
                    return detail(404, "Not found.");
                }
                let records = records(request);
                if records.is_empty() {
                    domain.rrsets.remove(&params["subname"]);
                    return Reply::status(204);
                }
                domain
                    .rrsets
                    .insert(params["subname"].clone(), records.clone());
                Reply::json(
                    200,
                    json!({ "subname": params["subname"], "type": "TXT", "ttl": 3600, "records": records }),
                )
            },
        );
        Self { api, domain }
    }

    fn solver(&self, token: &str, zone: Option<&str>) -> DesecDns {
        DesecDns::new(&DesecProvider {
            token: token.to_owned(),
            zone: zone.map(str::to_owned),
            api_url: Some(self.api.url().parse().unwrap()),
        })
        .unwrap()
    }
}

impl ContractFake for DesecFake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let subname = fqdn.strip_suffix(".example.com").unwrap();
        let domain = self.domain.lock().unwrap();
        domain
            .rrsets
            .get(subname)
            .into_iter()
            .flatten()
            .map(|record| record.trim_matches('"').to_owned())
            .collect()
    }

    fn accept_only(&self, credential: &str) {
        credential.clone_into(&mut self.domain.lock().unwrap().token);
    }

    fn fail_next_write(&self) {
        self.api.fail(
            "PATCH",
            "/domains/{name}/rrsets/{subname}/{type}",
            1,
            detail(
                429,
                "Request was throttled. Expected available in 1 second.",
            )
            .header("retry-after", "1"),
        );
    }
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = DesecFake::start().await;
    dns_contract::run(&fake, ["first-token", "second-token"], |token| {
        Arc::new(fake.solver(token, None))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = DesecFake::start().await;
    fake.accept_only("token");
    let dns = fake.solver("token", None);
    dns.present("_acme-challenge.APP.example.com", "v4lue")
        .await
        .unwrap();
    dns.present("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let requests = fake.api.requests();
    assert_eq!(
        fake.api.lines(),
        [
            "GET /domains/?owns_qname=_acme-challenge.app.example.com",
            "GET /domains/example.com/rrsets/_acme-challenge.app/TXT/",
            "GET /domains/example.com/",
            "POST /domains/example.com/rrsets/",
            "GET /domains/example.com/rrsets/_acme-challenge.app/TXT/",
            "GET /domains/example.com/rrsets/_acme-challenge.app/TXT/",
            "PATCH /domains/example.com/rrsets/_acme-challenge.app/TXT/",
        ],
        "a value already present costs no write"
    );
    assert_eq!(
        requests[3].json(),
        json!({ "subname": "_acme-challenge.app", "type": "TXT", "ttl": 3600, "records": ["\"v4lue\""] })
    );
    assert_eq!(requests[6].json(), json!({ "records": [] }));
    assert_eq!(requests[3].header("authorization"), Some("Token token"));
    assert_eq!(requests[3].header("content-type"), Some("application/json"));
    assert_eq!(fake.txt_values(dns_contract::FQDN), Vec::<String>::new());
}

#[tokio::test]
async fn concurrent_presents_on_one_name_keep_both_values() {
    let fake = DesecFake::start().await;
    fake.accept_only("token");
    let dns = fake.solver("token", Some("example.com"));
    let (apex, wildcard) = tokio::join!(
        dns.present(dns_contract::FQDN, "apex"),
        dns.present(dns_contract::FQDN, "wildcard")
    );
    apex.unwrap();
    wildcard.unwrap();
    let mut values = fake.txt_values(dns_contract::FQDN);
    values.sort();
    assert_eq!(values, ["apex", "wildcard"]);
}

#[tokio::test]
async fn reports_errors_with_the_providers_detail() {
    let fake = DesecFake::start().await;
    fake.accept_only("token");
    let error = fake
        .solver("wrong", Some("example.com"))
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap_err();
    assert!(
        error.0.contains("401 Unauthorized: Invalid token."),
        "{error}"
    );
    let foreign = fake
        .solver("token", None)
        .present("_acme-challenge.example.org", "x")
        .await
        .unwrap_err();
    assert!(foreign.0.contains("no deSEC zone holds"), "{foreign}");
    fake.solver("token", None)
        .cleanup(dns_contract::FQDN, "never-presented")
        .await
        .unwrap();
}

/// Against the real deSEC API: `RDOCK_LIVE_DNS_DESEC=1`, a token in `RDOCK_DESEC_TOKEN` and a
/// domain in `RDOCK_DESEC_DOMAIN`. Run on the test server only, never in CI.
#[tokio::test]
async fn live() {
    if std::env::var("RDOCK_LIVE_DNS_DESEC").as_deref() != Ok("1") {
        return;
    }
    let domain = std::env::var("RDOCK_DESEC_DOMAIN").unwrap();
    let dns = DesecDns::new(&DesecProvider {
        token: "${env:RDOCK_DESEC_TOKEN}".to_owned(),
        zone: None,
        api_url: None,
    })
    .unwrap();
    let fqdn = format!("_acme-challenge.rdock-live.{domain}");
    dns.present(&fqdn, "rdock-live-a").await.unwrap();
    dns.present(&fqdn, "rdock-live-b").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-a").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-b").await.unwrap();
}
