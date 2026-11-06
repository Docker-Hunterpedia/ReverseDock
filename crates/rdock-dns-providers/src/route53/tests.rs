//! The adapter against a fake Route 53 API that keeps record sets and changes like the real
//! one and checks every request's `SigV4` signature with the accepted secret. Requests and
//! answers follow the API reference (checked 2026-11-07):
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZonesByName.html>
//! (`GET /2013-04-01/hostedzonesbyname?dnsname=&maxitems=`, zones from `dnsname` on, names with
//! a trailing dot, `Config/PrivateZone`),
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html>
//! (`GET /2013-04-01/hostedzone/{Id}/rrset?name=&type=&maxitems=`, sets from `name` on),
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html>
//! (`POST /2013-04-01/hostedzone/{Id}/rrset/`, a DELETE matching the set exactly) and
//! <https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html>.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Recorded, Reply};

use super::*;

const PUBLIC: &str = "Z1PUBLIC";
const PRIVATE: &str = "Z9PRIVATE";
const NS: &str = r#"xmlns="https://route53.amazonaws.com/doc/2013-04-01/""#;

#[derive(Default)]
struct State {
    secret: String,
    /// Hosted zones: (ID, name with the trailing dot, private).
    zones: Vec<(String, String, bool)>,
    /// TXT sets of the public zone by name (with the trailing dot): TTL and values as stored.
    sets: BTreeMap<String, (u64, Vec<String>)>,
    next_change: u32,
    /// `GetChange` answers `PENDING` this many times before `INSYNC`.
    pending_polls: u32,
}

fn error(status: u16, code: &str, message: &str) -> Reply {
    Reply::status(status)
        .header("content-type", "text/xml")
        .body(format!(
            "<ErrorResponse {NS}><Error><Type>Sender</Type><Code>{code}</Code><Message>{message}</Message></Error><RequestId>r</RequestId></ErrorResponse>"
        ))
}

fn xml_reply(body: &str) -> Reply {
    Reply::status(200)
        .header("content-type", "text/xml")
        .body(format!(r#"<?xml version="1.0"?>{body}"#))
}

/// Whether the request carries a valid `SigV4` signature made with `secret` for Route 53 in
/// `us-east-1`, recomputed over the headers it says it signed.
fn signed_with(request: &Recorded, secret: &str) -> bool {
    let Some(authorization) = request.header("authorization") else {
        return false;
    };
    let field = |name: &str| {
        authorization
            .split(&format!("{name}="))
            .nth(1)
            .map(|rest| rest.split(',').next().unwrap_or_default().trim())
            .unwrap_or_default()
    };
    let credential: Vec<&str> = field("Credential").split('/').collect();
    assert_eq!(
        credential[2..],
        ["us-east-1", "route53", "aws4_request"],
        "{authorization}"
    );
    let signed: Vec<&str> = field("SignedHeaders").split(';').collect();
    assert!(signed.contains(&"host") && signed.contains(&"x-amz-date"));
    let query = request
        .query
        .as_ref()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let mut builder = Request::builder()
        .method(request.method.clone())
        .uri(format!(
            "http://{}{}{query}",
            request.header("host").unwrap(),
            request.path
        ));
    for name in &signed {
        builder = builder.header(*name, request.header(name).unwrap());
    }
    let rebuilt = builder.body(request.body.clone()).unwrap();
    let scope = Scope {
        region: "us-east-1",
        service: "route53",
    };
    let timestamp = request.header("x-amz-date").unwrap();
    sigv4::signature(&rebuilt, secret, &scope, timestamp).1 == field("Signature")
}

/// The change in a `ChangeResourceRecordSetsRequest`: action, name, TTL, values.
fn parse_change(body: &[u8]) -> (String, String, u64, Vec<String>) {
    let body = std::str::from_utf8(body).unwrap();
    assert!(
        body.contains(&format!("<ChangeResourceRecordSetsRequest {NS}>")),
        "{body}"
    );
    let changes = xml::elements(body, "Change");
    assert_eq!(changes.len(), 1, "one change per batch");
    let change = changes[0];
    assert_eq!(xml::text(change, "Type").unwrap(), "TXT");
    let values = xml::elements(change, "Value")
        .into_iter()
        .map(|v| xml::unescape(v).unwrap())
        .collect();
    (
        xml::text(change, "Action").unwrap(),
        xml::text(change, "Name").unwrap(),
        xml::text(change, "TTL").unwrap().parse().unwrap(),
        values,
    )
}

/// One public hosted zone, `example.com`.
struct Route53Fake {
    api: FakeApi,
    state: Arc<Mutex<State>>,
}

impl Route53Fake {
    #[allow(clippy::too_many_lines)] // one route table, read top to bottom
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let state = Arc::new(Mutex::new(State {
            zones: vec![(
                format!("/hostedzone/{PUBLIC}"),
                "example.com.".to_owned(),
                false,
            )],
            ..State::default()
        }));
        let shared = state.clone();
        api.guard(move |request| {
            let secret = shared.lock().unwrap().secret.clone();
            (!signed_with(request, &secret)).then(|| {
                error(
                    403,
                    "SignatureDoesNotMatch",
                    "The request signature we calculated does not match the signature you provided.",
                )
            })
        });
        let shared = state.clone();
        api.route("GET", "/2013-04-01/hostedzonesbyname", move |request, _| {
            let name = format!("{}.", request.query_param("dnsname").unwrap());
            assert_eq!(request.query_param("maxitems").as_deref(), Some("10"));
            let state = shared.lock().unwrap();
            let mut zones: Vec<_> = state.zones.iter().filter(|z| z.1 == name).collect();
            let unrelated = ("/hostedzone/Z5OTHER".to_owned(), "example.net.".to_owned(), false);
            if zones.is_empty() {
                // The list starts at `dnsname`: without a match, the next zone comes first.
                zones.push(&unrelated);
            }
            let listed: String = zones
                .iter()
                .map(|(id, name, private)| {
                    format!("<HostedZone><Id>{id}</Id><Name>{name}</Name><CallerReference>c</CallerReference><Config><PrivateZone>{private}</PrivateZone></Config><ResourceRecordSetCount>2</ResourceRecordSetCount></HostedZone>")
                })
                .collect::<Vec<_>>()
                .concat();
            xml_reply(&format!(
                "<ListHostedZonesByNameResponse {NS}><HostedZones>{listed}</HostedZones><DNSName>{name}</DNSName><IsTruncated>false</IsTruncated><MaxItems>10</MaxItems></ListHostedZonesByNameResponse>"
            ))
        });
        let shared = state.clone();
        api.route("GET", "/2013-04-01/hostedzone/{id}/rrset", move |request, params| {
            if params["id"] != PUBLIC {
                return error(404, "NoSuchHostedZone", "No hosted zone found");
            }
            let name = format!("{}.", request.query_param("name").unwrap());
            assert_eq!(request.query_param("type").as_deref(), Some("TXT"));
            let state = shared.lock().unwrap();
            let set = match state.sets.get(&name) {
                Some((ttl, values)) => {
                    let records = resource_records(values);
                    format!("<ResourceRecordSet><Name>{name}</Name><Type>TXT</Type><TTL>{ttl}</TTL><ResourceRecords>{records}</ResourceRecords></ResourceRecordSet>")
                }
                // The list starts at `name`: without the set, the next one comes first.
                None => "<ResourceRecordSet><Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL><ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>".to_owned(),
            };
            xml_reply(&format!(
                "<ListResourceRecordSetsResponse {NS}><ResourceRecordSets>{set}</ResourceRecordSets><IsTruncated>true</IsTruncated><MaxItems>1</MaxItems></ListResourceRecordSetsResponse>"
            ))
        });
        let shared = state.clone();
        api.route("POST", "/2013-04-01/hostedzone/{id}/rrset", move |request, params| {
            assert!(request.path.ends_with("/rrset/"), "{}", request.path);
            if params["id"] == PRIVATE {
                return error(403, "AccessDenied", "writes to the private zone are not allowed");
            }
            if params["id"] != PUBLIC {
                return error(404, "NoSuchHostedZone", "No hosted zone found");
            }
            let (action, name, ttl, values) = parse_change(&request.body);
            let mut state = shared.lock().unwrap();
            match action.as_str() {
                "UPSERT" => {
                    state.sets.insert(name, (ttl, values));
                }
                "DELETE" if state.sets.get(&name) == Some(&(ttl, values.clone())) => {
                    state.sets.remove(&name);
                }
                _ => {
                    return Reply::status(400).body(format!(
                        "<InvalidChangeBatch {NS}><Messages><Message>Tried to delete resource record set [name='{name}', type='TXT'] but the values provided do not match the current values</Message></Messages></InvalidChangeBatch>"
                    ));
                }
            }
            state.next_change += 1;
            xml_reply(&format!(
                "<ChangeResourceRecordSetsResponse {NS}><ChangeInfo><Id>/change/C{}</Id><Status>PENDING</Status><SubmittedAt>2026-11-07T00:00:00.000Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>",
                state.next_change
            ))
        });
        let shared = state.clone();
        api.route("GET", "/2013-04-01/change/{id}", move |_, params| {
            let mut state = shared.lock().unwrap();
            let status = if state.pending_polls > 0 {
                state.pending_polls -= 1;
                "PENDING"
            } else {
                "INSYNC"
            };
            xml_reply(&format!(
                "<GetChangeResponse {NS}><ChangeInfo><Id>/change/{}</Id><Status>{status}</Status><SubmittedAt>2026-11-07T00:00:00.000Z</SubmittedAt></ChangeInfo></GetChangeResponse>",
                params["id"]
            ))
        });
        Self { api, state }
    }

    fn provider(&self, secret: &str) -> Route53Provider {
        Route53Provider {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: secret.to_owned(),
            session_token: None,
            hosted_zone_id: None,
            region: None,
            api_url: Some(self.api.url().parse().unwrap()),
        }
    }

    fn solver(&self, secret: &str) -> Route53Dns {
        Route53Dns::new(&self.provider(secret)).unwrap()
    }
}

impl ContractFake for Route53Fake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .sets
            .get(&format!("{fqdn}."))
            .map(|(_, values)| {
                values
                    .iter()
                    .map(|v| v.trim_matches('"').to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn accept_only(&self, credential: &str) {
        credential.clone_into(&mut self.state.lock().unwrap().secret);
    }

    fn fail_next_write(&self) {
        self.api.fail(
            "POST",
            "/2013-04-01/hostedzone/{id}/rrset",
            1,
            error(400, "Throttling", "Rate exceeded"),
        );
    }

    fn add_private_zone(&self) {
        self.state.lock().unwrap().zones.push((
            format!("/hostedzone/{PRIVATE}"),
            "app.example.com.".to_owned(),
            true,
        ));
    }
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = Route53Fake::start().await;
    dns_contract::run(&fake, ["first-secret", "second-secret"], |secret| {
        Arc::new(fake.solver(secret))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = Route53Fake::start().await;
    fake.accept_only("secret");
    let dns = fake.solver("secret");
    dns.present("_acme-challenge.APP.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let requests = fake.api.requests();
    assert_eq!(
        fake.api.lines(),
        [
            "GET /2013-04-01/hostedzonesbyname?dnsname=_acme-challenge.app.example.com&maxitems=10",
            "GET /2013-04-01/hostedzonesbyname?dnsname=app.example.com&maxitems=10",
            "GET /2013-04-01/hostedzonesbyname?dnsname=example.com&maxitems=10",
            "GET /2013-04-01/hostedzone/Z1PUBLIC/rrset?name=_acme-challenge.app.example.com&type=TXT&maxitems=1",
            "POST /2013-04-01/hostedzone/Z1PUBLIC/rrset/",
            "GET /2013-04-01/change/C1",
            "GET /2013-04-01/hostedzone/Z1PUBLIC/rrset?name=_acme-challenge.app.example.com&type=TXT&maxitems=1",
            "POST /2013-04-01/hostedzone/Z1PUBLIC/rrset/",
        ]
    );
    assert_eq!(
        String::from_utf8_lossy(&requests[4].body),
        concat!(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">"#,
            "<ChangeBatch><Changes><Change><Action>UPSERT</Action><ResourceRecordSet>",
            "<Name>_acme-challenge.app.example.com.</Name><Type>TXT</Type><TTL>60</TTL>",
            "<ResourceRecords><ResourceRecord><Value>&quot;v4lue&quot;</Value></ResourceRecord></ResourceRecords>",
            "</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"
        )
    );
    assert_eq!(parse_change(&requests[7].body).0, "DELETE");
    assert_eq!(requests[4].header("content-type"), Some("application/xml"));
    let authorization = requests[4].header("authorization").unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
            && authorization.contains(
                "/us-east-1/route53/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature="
            ),
        "{authorization}"
    );
    assert_eq!(fake.txt_values(dns_contract::FQDN), Vec::<String>::new());
}

#[tokio::test]
async fn waits_for_insync_and_retries_a_concurrent_change() {
    let fake = Route53Fake::start().await;
    fake.accept_only("secret");
    fake.state.lock().unwrap().pending_polls = 1;
    fake.api.fail(
        "POST",
        "/2013-04-01/hostedzone/{id}/rrset",
        1,
        error(
            400,
            "PriorRequestNotComplete",
            "The request was rejected because Route 53 was still processing a prior request.",
        ),
    );
    let mut provider = fake.provider("secret");
    provider.hosted_zone_id = Some("/hostedzone/Z1PUBLIC".to_owned());
    let dns = Route53Dns::new(&provider).unwrap();
    dns.present(dns_contract::FQDN, "x").await.unwrap();
    let lines = fake.api.lines();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("GET /2013-04-01/change/C1"))
            .count(),
        2,
        "polled until INSYNC: {lines:?}"
    );
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("POST")).count(),
        2,
        "PriorRequestNotComplete was retried"
    );
    assert!(
        !lines.iter().any(|l| l.contains("hostedzonesbyname")),
        "the configured zone is used"
    );
}

#[tokio::test]
async fn concurrent_presents_on_one_name_keep_both_values() {
    let fake = Route53Fake::start().await;
    fake.accept_only("secret");
    let dns = fake.solver("secret");
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
async fn sends_the_session_token_and_reports_aws_errors() {
    let fake = Route53Fake::start().await;
    fake.accept_only("secret");
    let mut provider = fake.provider("secret");
    provider.session_token = Some("session".to_owned());
    Route53Dns::new(&provider)
        .unwrap()
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap();
    let requests = fake.api.requests();
    assert_eq!(requests[0].header("x-amz-security-token"), Some("session"));
    assert!(
        requests[0]
            .header("authorization")
            .unwrap()
            .contains("x-amz-security-token")
    );

    let error = fake
        .solver("wrong")
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap_err();
    assert!(
        error.0.contains("403 Forbidden: The request signature we calculated does not match the signature you provided. (SignatureDoesNotMatch)"),
        "{error}"
    );
    let foreign = fake
        .solver("secret")
        .present("_acme-challenge.example.org", "x")
        .await
        .unwrap_err();
    assert!(foreign.0.contains("no Route 53 zone holds"), "{foreign}");
}

/// Against the real Route 53 API: `RDOCK_LIVE_DNS_ROUTE53=1`, the key pair in
/// `RDOCK_ROUTE53_ACCESS_KEY_ID` and `RDOCK_ROUTE53_SECRET_ACCESS_KEY`, and a public hosted
/// zone's name in `RDOCK_ROUTE53_DOMAIN`. Run on the test server only, never in CI.
#[tokio::test]
async fn live() {
    if std::env::var("RDOCK_LIVE_DNS_ROUTE53").as_deref() != Ok("1") {
        return;
    }
    let domain = std::env::var("RDOCK_ROUTE53_DOMAIN").unwrap();
    let dns = Route53Dns::new(&Route53Provider {
        access_key_id: "${env:RDOCK_ROUTE53_ACCESS_KEY_ID}".to_owned(),
        secret_access_key: "${env:RDOCK_ROUTE53_SECRET_ACCESS_KEY}".to_owned(),
        session_token: None,
        hosted_zone_id: None,
        region: None,
        api_url: None,
    })
    .unwrap();
    let fqdn = format!("_acme-challenge.rdock-live.{domain}");
    dns.present(&fqdn, "rdock-live-a").await.unwrap();
    dns.present(&fqdn, "rdock-live-b").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-a").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-b").await.unwrap();
}
