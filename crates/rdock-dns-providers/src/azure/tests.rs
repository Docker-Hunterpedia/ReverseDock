//! The adapter against a fake of Microsoft Entra ID, the instance metadata service and Azure
//! Resource Manager. Requests follow (checked 2026-11-07):
//! <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>
//! (`POST /{tenant}/oauth2/v2.0/token` with `client_id`, `scope` `…/.default`, `grant_type`
//! `client_credentials`, and `client_secret` or `client_assertion_type` + `client_assertion`),
//! <https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials> (PS256,
//! `x5t#S256`, `aud`, `iss` = `sub` = client ID, `jti`, `nbf`, `exp`),
//! <https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token>
//! (`GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=…` with `Metadata:
//! true`, `expires_in` as a string) and
//! <https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update?view=rest-dns-2018-05-01>
//! (`PUT …/dnsZones/{zone}/TXT/{relativeRecordSetName}?api-version=2018-05-01` with
//! `{properties: {TTL, TXTRecords: [{value: […]}]}}`, `If-Match`, `If-None-Match: *`, `412`).

use std::collections::BTreeMap;
use std::sync::Mutex;

use rdock_testkit::dns_contract::{self, ContractFake};
use rdock_testkit::fake_api::{FakeApi, Recorded, Reply};
use ring::signature::RSA_PSS_2048_8192_SHA256;

use super::*;
use crate::testdata::{TEST_ONLY_CERT_A, TEST_ONLY_KEY_A, jwt_part, jwt_verifies};

const TENANT: &str = "00000000-0000-0000-0000-00000000000a";
const CLIENT: &str = "00000000-0000-0000-0000-00000000000c";
const ZONE: &str =
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com";

/// What the fake accepts as proof of identity.
#[derive(Default)]
enum Accepts {
    #[default]
    Nothing,
    Secret(String),
    /// The certificate's SHA-256 thumbprint (base64url) and public key.
    Certificate(String, Vec<u8>),
    ManagedIdentity,
}

#[derive(Default)]
struct State {
    accepts: Accepts,
    /// The scope (and IMDS resource) tokens must be asked for.
    management: String,
    /// The token issued for the current identity.
    token: String,
    issued: u32,
    /// TXT record sets by relative name: etag, TTL, values.
    sets: BTreeMap<String, (String, u64, Vec<String>)>,
    next_etag: u32,
}

impl State {
    fn issue(&mut self) -> String {
        self.issued += 1;
        self.token = format!("az-token-{}", self.issued);
        self.token.clone()
    }
}

fn arm_error(status: u16, code: &str, message: &str) -> Reply {
    Reply::json(
        status,
        json!({ "error": { "code": code, "message": message } }),
    )
}

fn entra_error(description: &str) -> Reply {
    Reply::json(
        401,
        json!({ "error": "invalid_client", "error_description": description }),
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

fn certificate_accepted(assertion: &str, thumbprint: &str, public_der: &[u8]) -> bool {
    let header = jwt_part(assertion, 0);
    let claims = jwt_part(assertion, 1);
    header["alg"] == "PS256"
        && header["x5t#S256"] == thumbprint
        && claims["aud"] == format!("https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token")
        && claims["iss"] == CLIENT
        && claims["sub"] == CLIENT
        && claims["jti"].as_str().is_some_and(|id| id.len() == 32)
        && claims["exp"].as_u64().unwrap() - claims["nbf"].as_u64().unwrap() <= 600
        && jwt_verifies(assertion, public_der, &RSA_PSS_2048_8192_SHA256)
}

fn record_set(name: &str, etag: &str, ttl: u64, values: &[String]) -> Value {
    let records: Vec<Value> = values.iter().map(|v| json!({ "value": [v] })).collect();
    json!({
        "id": format!("{ZONE}/TXT/{name}"),
        "name": name,
        "type": "Microsoft.Network/dnszones/TXT",
        "etag": etag,
        "properties": { "TTL": ttl, "fqdn": format!("{name}.example.com."), "TXTRecords": records },
    })
}

/// One zone, `example.com`, in subscription `sub` and resource group `rg`.
struct AzureFake {
    api: FakeApi,
    state: Arc<Mutex<State>>,
}

impl AzureFake {
    #[allow(clippy::too_many_lines)] // one route table, read top to bottom
    async fn start() -> Self {
        let api = FakeApi::start().await;
        let state = Arc::new(Mutex::new(State {
            management: "https://management.azure.com".to_owned(),
            ..State::default()
        }));
        let shared = state.clone();
        api.guard(move |request| {
            if !request.path.starts_with("/subscriptions/") {
                return None;
            }
            assert_eq!(
                request.query_param("api-version").as_deref(),
                Some("2018-05-01")
            );
            let expected = format!("Bearer {}", shared.lock().unwrap().token);
            (request.header("authorization") != Some(expected.as_str())).then(|| {
                arm_error(
                    401,
                    "InvalidAuthenticationToken",
                    "The access token is invalid.",
                )
            })
        });
        let shared = state.clone();
        api.route("POST", "/{tenant}/oauth2/v2.0/token", move |request, params| {
            assert_eq!(params["tenant"], TENANT);
            let mut state = shared.lock().unwrap();
            assert_eq!(form_param(request, "client_id").as_deref(), Some(CLIENT));
            assert_eq!(form_param(request, "grant_type").as_deref(), Some("client_credentials"));
            assert_eq!(
                form_param(request, "scope"),
                Some(format!("{}/.default", state.management))
            );
            let accepted = match &state.accepts {
                Accepts::Secret(secret) => {
                    form_param(request, "client_secret").as_deref() == Some(secret.as_str())
                }
                Accepts::Certificate(thumbprint, public) => {
                    form_param(request, "client_assertion_type").as_deref()
                        == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                        && form_param(request, "client_assertion")
                            .is_some_and(|a| certificate_accepted(&a, thumbprint, public))
                }
                Accepts::Nothing | Accepts::ManagedIdentity => false,
            };
            if !accepted {
                return entra_error("AADSTS7000215: Invalid client secret provided.");
            }
            let token = state.issue();
            Reply::json(
                200,
                json!({ "token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599, "access_token": token }),
            )
        });
        let shared = state.clone();
        api.route("GET", "/metadata/identity/oauth2/token", move |request, _| {
            let mut state = shared.lock().unwrap();
            assert_eq!(request.header("metadata"), Some("true"));
            assert_eq!(request.query_param("api-version").as_deref(), Some("2018-02-01"));
            assert_eq!(
                request.query_param("resource"),
                Some(format!("{}/", state.management))
            );
            if !matches!(state.accepts, Accepts::ManagedIdentity) {
                return Reply::json(
                    400,
                    json!({ "error": "invalid_request", "error_description": "Identity not found" }),
                );
            }
            let token = state.issue();
            Reply::json(
                200,
                json!({ "access_token": token, "expires_in": "3599", "resource": "https://management.azure.com/", "token_type": "Bearer" }),
            )
        });
        let txt = format!("{ZONE}/TXT/{{name}}");
        let shared = state.clone();
        api.route("GET", &txt, move |_, params| {
            let state = shared.lock().unwrap();
            match state.sets.get(&params["name"]) {
                Some((etag, ttl, values)) => {
                    Reply::json(200, record_set(&params["name"], etag, *ttl, values))
                }
                None => arm_error(404, "NotFound", "The resource record set was not found."),
            }
        });
        let shared = state.clone();
        api.route("PUT", &txt, move |request, params| {
            let mut state = shared.lock().unwrap();
            let name = params["name"].clone();
            if let Some(refused) = precondition(request, state.sets.get(&name)) {
                return refused;
            }
            let body = request.json();
            let values: Vec<String> = body["properties"]["TXTRecords"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| {
                    let parts = record["value"].as_array().unwrap();
                    assert_eq!(parts.len(), 1, "one string per value");
                    parts[0].as_str().unwrap().to_owned()
                })
                .collect();
            let ttl = body["properties"]["TTL"].as_u64().unwrap();
            state.next_etag += 1;
            let etag = format!("etag-{}", state.next_etag);
            let created = !state.sets.contains_key(&name);
            state
                .sets
                .insert(name.clone(), (etag.clone(), ttl, values.clone()));
            Reply::json(
                if created { 201 } else { 200 },
                record_set(&name, &etag, ttl, &values),
            )
        });
        let shared = state.clone();
        api.route("DELETE", &txt, move |request, params| {
            let mut state = shared.lock().unwrap();
            if let Some(refused) = precondition(request, state.sets.get(&params["name"])) {
                return refused;
            }
            state.sets.remove(&params["name"]);
            Reply::status(200)
        });
        Self { api, state }
    }

    fn provider(&self) -> AzureDnsProvider {
        AzureDnsProvider {
            tenant_id: Some(TENANT.to_owned()),
            client_id: Some(CLIENT.to_owned()),
            client_secret: None,
            client_certificate: None,
            managed_identity: false,
            subscription_id: "sub".to_owned(),
            resource_group: "rg".to_owned(),
            zone: "example.com".to_owned(),
            environment: AzureEnvironment::Public,
            api_url: Some(self.api.url().parse().unwrap()),
        }
    }

    fn with_secret(&self, reference: &str) -> AzureDns {
        let mut provider = self.provider();
        provider.client_secret = Some(reference.to_owned());
        AzureDns::new(&provider).unwrap()
    }
}

/// `If-Match` must name the current etag, `If-None-Match: *` that there is none.
fn precondition(request: &Recorded, current: Option<&(String, u64, Vec<String>)>) -> Option<Reply> {
    let holds = match (
        request.header("if-match"),
        request.header("if-none-match"),
        current,
    ) {
        (Some(etag), None, Some((current, _, _))) => etag == current,
        (None, Some("*"), None) => true,
        _ => false,
    };
    (!holds).then(|| {
        arm_error(
            412,
            "PreconditionFailed",
            "The condition 'If-Match' in the request was not satisfied.",
        )
    })
}

impl ContractFake for AzureFake {
    fn txt_values(&self, fqdn: &str) -> Vec<String> {
        let relative = fqdn.strip_suffix(".example.com").unwrap();
        let state = self.state.lock().unwrap();
        state
            .sets
            .get(relative)
            .map(|(_, _, values)| values.clone())
            .unwrap_or_default()
    }

    fn accept_only(&self, credential: &str) {
        self.state.lock().unwrap().accepts = Accepts::Secret(credential.to_owned());
    }

    fn fail_next_write(&self) {
        self.api.fail(
            "PUT",
            &format!("{ZONE}/TXT/{{name}}"),
            1,
            arm_error(429, "TooManyRequests", "The request is being throttled.")
                .header("retry-after", "1"),
        );
    }
}

#[tokio::test]
async fn passes_the_contract() {
    let fake = AzureFake::start().await;
    dns_contract::run(&fake, ["first-secret", "second-secret"], |reference| {
        Arc::new(fake.with_secret(reference))
    })
    .await;
}

#[tokio::test]
async fn sends_the_documented_requests() {
    let fake = AzureFake::start().await;
    fake.accept_only("secret");
    let dns = fake.with_secret("secret");
    dns.present("_acme-challenge.APP.example.com", "v4lue")
        .await
        .unwrap();
    dns.present("_acme-challenge.app.example.com", "w")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "v4lue")
        .await
        .unwrap();
    dns.cleanup("_acme-challenge.app.example.com", "w")
        .await
        .unwrap();
    let txt = format!("{ZONE}/TXT/_acme-challenge.app?api-version=2018-05-01");
    assert_eq!(
        fake.api.lines(),
        [
            format!("POST /{TENANT}/oauth2/v2.0/token"),
            format!("GET {txt}"),
            format!("PUT {txt}"),
            format!("GET {txt}"),
            format!("PUT {txt}"),
            format!("GET {txt}"),
            format!("PUT {txt}"),
            format!("GET {txt}"),
            format!("DELETE {txt}"),
        ]
    );
    let requests = fake.api.requests();
    assert_eq!(requests[2].header("if-none-match"), Some("*"));
    assert_eq!(
        requests[2].json(),
        json!({ "properties": { "TTL": 60, "TXTRecords": [{ "value": ["v4lue"] }] } })
    );
    assert_eq!(requests[4].header("if-match"), Some("etag-1"));
    assert_eq!(
        requests[4].json()["properties"]["TXTRecords"],
        json!([{ "value": ["v4lue"] }, { "value": ["w"] }])
    );
    assert_eq!(requests[8].header("if-match"), Some("etag-3"));
    assert_eq!(
        requests[2].header("authorization"),
        Some("Bearer az-token-1")
    );
    assert_eq!(fake.txt_values(dns_contract::FQDN), Vec::<String>::new());
}

#[tokio::test]
async fn a_changed_record_set_is_read_again() {
    let fake = AzureFake::start().await;
    fake.accept_only("secret");
    fake.api.fail(
        "PUT",
        &format!("{ZONE}/TXT/{{name}}"),
        1,
        arm_error(
            412,
            "PreconditionFailed",
            "The condition 'If-None-Match' in the request was not satisfied.",
        ),
    );
    fake.with_secret("secret")
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap();
    let lines = fake.api.lines();
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("GET")).count(),
        2,
        "{lines:?}"
    );
    assert_eq!(fake.txt_values(dns_contract::FQDN), ["x"]);
}

#[tokio::test]
async fn a_certificate_assertion_signs_in() {
    let fake = AzureFake::start().await;
    let certificate = CertificateDer::from_pem_slice(TEST_ONLY_CERT_A.as_bytes()).unwrap();
    let public = RsaKey::from_pem(TEST_ONLY_KEY_A.as_bytes(), "test")
        .unwrap()
        .public_der();
    fake.state.lock().unwrap().accepts = Accepts::Certificate(
        URL_SAFE_NO_PAD.encode(digest(&SHA256, &certificate)),
        public,
    );
    let dir = tempfile::tempdir().unwrap();
    let pem = dir.path().join("client.pem");
    std::fs::write(&pem, format!("{TEST_ONLY_CERT_A}{TEST_ONLY_KEY_A}")).unwrap();
    let mut provider = fake.provider();
    provider.client_certificate = Some(format!("${{file:{}}}", pem.display()));
    AzureDns::new(&provider)
        .unwrap()
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap();
    assert_eq!(fake.txt_values(dns_contract::FQDN), ["x"]);
}

#[tokio::test]
async fn a_managed_identity_signs_in_through_the_metadata_service() {
    let fake = AzureFake::start().await;
    fake.state.lock().unwrap().accepts = Accepts::ManagedIdentity;
    let mut provider = fake.provider();
    provider.tenant_id = None;
    provider.client_id = None;
    provider.managed_identity = true;
    AzureDns::new(&provider)
        .unwrap()
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap();
    assert_eq!(
        fake.api.lines()[0],
        "GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
    );
    assert_eq!(fake.txt_values(dns_contract::FQDN), ["x"]);
}

#[tokio::test]
async fn national_clouds_ask_for_their_own_resource_manager() {
    let fake = AzureFake::start().await;
    fake.accept_only("secret");
    fake.state.lock().unwrap().management = "https://management.usgovcloudapi.net".to_owned();
    let mut provider = fake.provider();
    provider.client_secret = Some("secret".to_owned());
    provider.environment = AzureEnvironment::UsGovernment;
    AzureDns::new(&provider)
        .unwrap()
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap();
    assert_eq!(
        cloud(AzureEnvironment::China).login,
        "https://login.partner.microsoftonline.cn"
    );
    assert_eq!(
        cloud(AzureEnvironment::China).management,
        "https://management.chinacloudapi.cn"
    );
}

#[tokio::test]
async fn sign_in_errors_carry_entras_message() {
    let fake = AzureFake::start().await;
    fake.accept_only("secret");
    let error = fake
        .with_secret("wrong")
        .present(dns_contract::FQDN, "x")
        .await
        .unwrap_err();
    assert!(
        error.0.contains(
            "401 Unauthorized: AADSTS7000215: Invalid client secret provided. (invalid_client)"
        ),
        "{error}"
    );
    let outside = fake
        .with_secret("secret")
        .present("_acme-challenge.example.org", "x")
        .await
        .unwrap_err();
    assert!(
        outside.0.contains("not in the configured zone"),
        "{outside}"
    );
}

/// Against the real Azure DNS: `RDOCK_LIVE_DNS_AZURE_DNS=1`, a service principal in
/// `RDOCK_AZURE_TENANT_ID`, `RDOCK_AZURE_CLIENT_ID` and `RDOCK_AZURE_CLIENT_SECRET`, and the
/// zone in `RDOCK_AZURE_SUBSCRIPTION_ID`, `RDOCK_AZURE_RESOURCE_GROUP` and `RDOCK_AZURE_ZONE`.
/// Run on the test server only, never in CI.
#[tokio::test]
async fn live() {
    if std::env::var("RDOCK_LIVE_DNS_AZURE_DNS").as_deref() != Ok("1") {
        return;
    }
    let var = |name: &str| std::env::var(name).unwrap();
    let zone = var("RDOCK_AZURE_ZONE");
    let dns = AzureDns::new(&AzureDnsProvider {
        tenant_id: Some(var("RDOCK_AZURE_TENANT_ID")),
        client_id: Some(var("RDOCK_AZURE_CLIENT_ID")),
        client_secret: Some("${env:RDOCK_AZURE_CLIENT_SECRET}".to_owned()),
        client_certificate: None,
        managed_identity: false,
        subscription_id: var("RDOCK_AZURE_SUBSCRIPTION_ID"),
        resource_group: var("RDOCK_AZURE_RESOURCE_GROUP"),
        zone: zone.clone(),
        environment: AzureEnvironment::Public,
        api_url: None,
    })
    .unwrap();
    let fqdn = format!("_acme-challenge.rdock-live.{zone}");
    dns.present(&fqdn, "rdock-live-a").await.unwrap();
    dns.present(&fqdn, "rdock-live-b").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-a").await.unwrap();
    dns.cleanup(&fqdn, "rdock-live-b").await.unwrap();
}
