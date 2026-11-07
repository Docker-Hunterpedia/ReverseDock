//! The adapter against a fake of Google's token endpoint and the Cloud DNS API. The token
//! endpoint checks the RS256 assertion as Google documents it
//! (<https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests>,
//! checked 2026-11-07: `iss`, `scope`, `aud` `https://oauth2.googleapis.com/token`, `iat`, `exp`
//! at most one hour later, form `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`); the
//! DNS fake follows <https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list>,
//! `…/resourceRecordSets/list` and `…/changes` (2026-11-07): zones with `visibility`, record
//! names with the trailing dot, and deletions that must match the current set exactly.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Recorded, Reply};
use ring::signature::RSA_PKCS1_2048_8192_SHA256;

use super::*;
use crate::testdata::{TEST_ONLY_KEY_A, TEST_ONLY_KEY_B, jwt_part, jwt_verifies};

const PROJECT: &str = "rdock-test";

/// A service account key file for a test-only key.
fn key_file(email: &str, pem: &str) -> String {
    json!({
        "type": "service_account",
        "project_id": PROJECT,
        "private_key_id": format!("kid-{email}"),
        "private_key": pem,
        "client_email": email,
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string()
}

#[derive(Default)]
struct State {
    /// The accepted service account and its public key.
    email: String,
    public_der: Vec<u8>,
    /// Zones: (name, DNS name with the trailing dot, visibility).
    zones: Vec<(String, String, String)>,
    /// TXT sets of `example-com` by name (with the trailing dot): TTL and rrdatas.
    sets: BTreeMap<String, (u64, Vec<String>)>,
    next_change: u32,
    /// Whether new changes are answered `pending` (followed until `done`) instead of `done`.
    pending_changes: bool,
}

fn google_error(code: u16, status: &str, message: &str) -> Reply {
    Reply::json(
        code,
        json!({ "error": { "code": code, "message": message, "status": status } }),
    )
}

fn form_param(request: &Recorded, name: &str) -> Option<String> {
    let body = std::str::from_utf8(&request.body).unwrap();
    body.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .into_owned()
        })
    })
}

/// One project with the public zone `example-com` for `example.com.`.
struct GoogleFake {
    api: FakeApi,
    state: Arc<Mutex<State>>,
}

impl GoogleFake {
    #[allow(clippy::too_many_lines)] // one route table, read top to bottom
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let state = Arc::new(Mutex::new(State {
            zones: vec![(
                "example-com".to_owned(),
                "example.com.".to_owned(),
                "public".to_owned(),
            )],
            ..State::default()
        }));
        let shared = state.clone();
        api.guard(move |request| {
            if request.path == "/token" {
                return None;
            }
            let expected = format!("Bearer ya29.{}", shared.lock().unwrap().email);
            (request.header("authorization") != Some(expected.as_str())).then(|| {
                google_error(
                    401,
                    "UNAUTHENTICATED",
                    "Request had invalid authentication credentials.",
                )
            })
        });
        let shared = state.clone();
        api.route("POST", "/token", move |request, _| {
            assert_eq!(
                request.header("content-type"),
                Some("application/x-www-form-urlencoded")
            );
            assert_eq!(
                form_param(request, "grant_type").as_deref(),
                Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
            );
            let assertion = form_param(request, "assertion").unwrap();
            let state = shared.lock().unwrap();
            let claims = jwt_part(&assertion, 1);
            let valid = jwt_part(&assertion, 0)["alg"] == "RS256"
                && claims["iss"] == state.email.as_str()
                && claims["aud"] == TOKEN_URL
                && claims["scope"] == SCOPE
                && claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap() <= 3600
                && jwt_verifies(&assertion, &state.public_der, &RSA_PKCS1_2048_8192_SHA256);
            if valid {
                Reply::json(
                    200,
                    json!({ "access_token": format!("ya29.{}", state.email), "expires_in": 3599, "token_type": "Bearer" }),
                )
            } else {
                Reply::json(
                    400,
                    json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." }),
                )
            }
        });
        let shared = state.clone();
        api.route(
            "GET",
            "/dns/v1/projects/{project}/managedZones",
            move |request, params| {
                assert_eq!(params["project"], PROJECT);
                let dns_name = request.query_param("dnsName").unwrap();
                let state = shared.lock().unwrap();
                let zones: Vec<Value> = state
                    .zones
                    .iter()
                    .filter(|(_, name, _)| *name == dns_name)
                    .map(|(id, name, visibility)| {
                        json!({ "name": id, "dnsName": name, "visibility": visibility, "kind": "dns#managedZone" })
                    })
                    .collect();
                Reply::json(200, json!({ "managedZones": zones }))
            },
        );
        let shared = state.clone();
        api.route(
            "GET",
            "/dns/v1/projects/{project}/managedZones/{zone}/rrsets",
            move |request, params| {
                assert_eq!(params["zone"], "example-com");
                assert_eq!(request.query_param("type").as_deref(), Some("TXT"));
                let name = request.query_param("name").unwrap();
                let state = shared.lock().unwrap();
                let sets: Vec<Value> = state
                    .sets
                    .get(&name)
                    .map(|(ttl, rrdatas)| json!({ "name": name, "type": "TXT", "ttl": ttl, "rrdatas": rrdatas }))
                    .into_iter()
                    .collect();
                Reply::json(200, json!({ "rrsets": sets }))
            },
        );
        let shared = state.clone();
        api.route(
            "POST",
            "/dns/v1/projects/{project}/managedZones/{zone}/changes",
            move |request, params| {
                if params["zone"] != "example-com" {
                    return google_error(403, "PERMISSION_DENIED", "Forbidden");
                }
                let change = request.json();
                let mut state = shared.lock().unwrap();
                for deletion in change["deletions"].as_array().unwrap() {
                    let name = deletion["name"].as_str().unwrap();
                    let current = state.sets.get(name).map(|(ttl, rrdatas)| {
                        json!({ "name": name, "type": "TXT", "ttl": ttl, "rrdatas": rrdatas })
                    });
                    if current.as_ref() != Some(deletion) {
                        return google_error(
                            412,
                            "FAILED_PRECONDITION",
                            "The resource record set to delete does not match the existing one.",
                        );
                    }
                    state.sets.remove(name);
                }
                for addition in change["additions"].as_array().unwrap() {
                    assert_eq!(addition["type"], "TXT");
                    let rrdatas: Vec<String> = addition["rrdatas"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|d| d.as_str().unwrap().to_owned())
                        .collect();
                    assert!(
                        rrdatas
                            .iter()
                            .all(|d| d.starts_with('"') && d.ends_with('"'))
                    );
                    let name = addition["name"].as_str().unwrap().to_owned();
                    assert!(name.ends_with('.'));
                    if state.sets.contains_key(&name) {
                        return google_error(
                            409,
                            "ALREADY_EXISTS",
                            "The resource record set already exists.",
                        );
                    }
                    state
                        .sets
                        .insert(name, (addition["ttl"].as_u64().unwrap(), rrdatas));
                }
                state.next_change += 1;
                let mut answer = change.clone();
                answer["id"] = state.next_change.to_string().into();
                answer["status"] = if state.pending_changes {
                    "pending"
                } else {
                    "done"
                }
                .into();
                Reply::json(200, answer)
            },
        );
        api.route(
            "GET",
            "/dns/v1/projects/{project}/managedZones/{zone}/changes/{id}",
            |_, params| Reply::json(200, json!({ "id": params["id"], "status": "done" })),
        );
        Self { api, state }
    }

    fn solver(&self, credentials_file: &Path, zone: Option<&str>) -> GoogleCloudDns {
        GoogleCloudDns::new(&GoogleCloudDnsProvider {
            credentials_file: credentials_file.to_owned(),
            project: None,
            zone: zone.map(str::to_owned),
            api_url: Some(self.api.url().parse().unwrap()),
        })
        .unwrap()
    }
}

impl ContractFake for GoogleFake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .sets
            .get(&format!("{fqdn}."))
            .map(|(_, data)| {
                data.iter()
                    .map(|d| d.trim_matches('"').to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn accept_only(&self, credential: &str) {
        let key: Value = serde_json::from_str(credential).unwrap();
        let public = RsaKey::from_pem(key["private_key"].as_str().unwrap().as_bytes(), "test")
            .unwrap()
            .public_der();
        let mut state = self.state.lock().unwrap();
        state.email = key["client_email"].as_str().unwrap().to_owned();
        state.public_der = public;
    }

    fn fail_next_write(&self) {
        self.api.fail(
            "POST",
            "/dns/v1/projects/{project}/managedZones/{zone}/changes",
            1,
            google_error(429, "RESOURCE_EXHAUSTED", "Quota exceeded.").header("retry-after", "1"),
        );
    }

    fn add_private_zone(&self) {
        self.state.lock().unwrap().zones.push((
            "app-private".to_owned(),
            "app.example.com.".to_owned(),
            "private".to_owned(),
        ));
    }
}

/// The path inside a `${file:…}` reference.
fn path_of(reference: &str) -> PathBuf {
    PathBuf::from(
        reference
            .strip_prefix("${file:")
            .and_then(|rest| rest.strip_suffix('}'))
            .unwrap(),
    )
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = GoogleFake::start().await;
    let first = key_file("first@rdock-test.iam.gserviceaccount.com", TEST_ONLY_KEY_A);
    let second = key_file("second@rdock-test.iam.gserviceaccount.com", TEST_ONLY_KEY_B);
    dns_contract::run(&fake, [&first, &second], |reference| {
        Arc::new(fake.solver(&path_of(reference), None))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = GoogleFake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("key.json");
    let key = key_file("svc@rdock-test.iam.gserviceaccount.com", TEST_ONLY_KEY_A);
    std::fs::write(&file, &key).unwrap();
    fake.accept_only(&key);
    fake.state.lock().unwrap().pending_changes = true;
    let dns = fake.solver(&file, None);
    dns.present("_acme-challenge.APP.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    let requests = fake.api.requests();
    let zone = "/dns/v1/projects/rdock-test/managedZones";
    let expected = [
        "POST /token".to_owned(),
        format!("GET {zone}?dnsName=_acme-challenge.app.example.com."),
        format!("GET {zone}?dnsName=app.example.com."),
        format!("GET {zone}?dnsName=example.com."),
        format!("GET {zone}/example-com/rrsets?name=_acme-challenge.app.example.com.&type=TXT"),
        format!("POST {zone}/example-com/changes"),
        format!("GET {zone}/example-com/changes/1"),
        format!("GET {zone}/example-com/rrsets?name=_acme-challenge.app.example.com.&type=TXT"),
        format!("POST {zone}/example-com/changes"),
        format!("GET {zone}/example-com/changes/2"),
    ];
    assert_eq!(
        fake.api.lines(),
        expected,
        "one token, pending changes followed"
    );
    let set = json!({ "name": "_acme-challenge.app.example.com.", "type": "TXT", "ttl": 60, "rrdatas": ["\"v4lue\""] });
    let changes: Vec<&Recorded> = requests
        .iter()
        .filter(|r| r.method == "POST" && r.path.ends_with("/changes"))
        .collect();
    assert_eq!(
        changes[0].json(),
        json!({ "additions": [set], "deletions": [] })
    );
    assert_eq!(
        changes[1].json(),
        json!({ "additions": [], "deletions": [set] })
    );
    let assertion = form_param(
        requests.iter().find(|r| r.path == "/token").unwrap(),
        "assertion",
    )
    .unwrap();
    assert_eq!(
        jwt_part(&assertion, 0)["kid"],
        "kid-svc@rdock-test.iam.gserviceaccount.com"
    );
    assert_eq!(fake.txt_values(dns_contract::FQDN), Vec::<String>::new());
}

#[test]
fn the_assertion_has_the_documented_claims() {
    let key = key_file("svc@rdock-test.iam.gserviceaccount.com", TEST_ONLY_KEY_A);
    let token = assertion(key.as_bytes(), 1_800_000_000).unwrap();
    assert_eq!(
        jwt_part(&token, 0),
        json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-svc@rdock-test.iam.gserviceaccount.com" })
    );
    assert_eq!(
        jwt_part(&token, 1),
        json!({
            "iss": "svc@rdock-test.iam.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": 1_800_000_000_u64,
            "exp": 1_800_003_600_u64,
        })
    );
    let public = RsaKey::from_pem(TEST_ONLY_KEY_A.as_bytes(), "test")
        .unwrap()
        .public_der();
    assert!(jwt_verifies(&token, &public, &RSA_PKCS1_2048_8192_SHA256));
    assert!(
        assertion(b"{}", 0)
            .unwrap_err()
            .0
            .contains("has no `private_key`")
    );
}

#[tokio::test]
async fn token_errors_carry_googles_message() {
    let fake = GoogleFake::start().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("key.json");
    std::fs::write(
        &file,
        key_file("svc@rdock-test.iam.gserviceaccount.com", TEST_ONLY_KEY_A),
    )
    .unwrap();
    fake.accept_only(&key_file(
        "other@rdock-test.iam.gserviceaccount.com",
        TEST_ONLY_KEY_B,
    ));
    let error = fake
        .solver(&file, Some("example-com"))
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap_err();
    assert!(
        error
            .0
            .contains("400 Bad Request: Invalid JWT Signature. (invalid_grant)"),
        "{error}"
    );
    let missing = fake
        .solver(&dir.path().join("missing.json"), Some("example-com"))
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap_err();
    assert!(missing.0.contains("cannot be read"), "{missing}");
}

/// Against the real Cloud DNS API: `RDOCK_LIVE_DNS_GOOGLE_CLOUD_DNS=1`, a service account key
/// file at `RDOCK_GOOGLE_CREDENTIALS_FILE` and a public zone's DNS name in
/// `RDOCK_GOOGLE_DOMAIN`. Run on the test server only, never in CI.
#[tokio::test]
async fn live() {
    if std::env::var("RDOCK_LIVE_DNS_GOOGLE_CLOUD_DNS").as_deref() != Ok("1") {
        return;
    }
    let domain = std::env::var("RDOCK_GOOGLE_DOMAIN").unwrap();
    let dns = GoogleCloudDns::new(&GoogleCloudDnsProvider {
        credentials_file: std::env::var("RDOCK_GOOGLE_CREDENTIALS_FILE")
            .unwrap()
            .into(),
        project: None,
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
