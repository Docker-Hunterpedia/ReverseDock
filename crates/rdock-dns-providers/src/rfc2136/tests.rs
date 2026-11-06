//! The adapter against the in-process TSIG-verifying server.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::op::OpCode;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm as WireAlgorithm;
use rdock_model::acme::TsigAlgorithm;
use rdock_testkit::dns_contract::{self, ContractFake, FQDN};

use super::fake_server::{FakeDnsServer, ServerKey};
use super::*;

const KEY: &str = "rdock-acme.";

fn secret(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn config(server: SocketAddr, secret: &str, algorithm: TsigAlgorithm) -> Rfc2136Provider {
    Rfc2136Provider {
        nameserver: server.to_string(),
        zone: None,
        tsig_key_name: Some(KEY.to_owned()),
        tsig_secret: Some(secret.to_owned()),
        tsig_algorithm: algorithm,
        transport: DnsTransport::Tcp,
        insecure_unsigned: false,
    }
}

async fn contract(transport: DnsTransport) {
    let (first, second) = (secret(1), secret(2));
    let server =
        FakeDnsServer::start(Some(ServerKey::new(KEY, WireAlgorithm::HmacSha256, &first))).await;
    dns_contract::run(&server, [&first, &second], |reference| {
        let config = Rfc2136Provider {
            transport,
            ..config(server.addr, reference, TsigAlgorithm::HmacSha256)
        };
        Arc::new(Rfc2136Dns::new(&config).unwrap())
    })
    .await;
}

#[tokio::test]
async fn passes_the_contract_over_tcp() {
    contract(DnsTransport::Tcp).await;
}

#[tokio::test]
async fn passes_the_contract_over_udp() {
    contract(DnsTransport::Udp).await;
}

#[tokio::test]
async fn adds_and_deletes_single_records_never_the_rrset() {
    let key = secret(3);
    let server =
        FakeDnsServer::start(Some(ServerKey::new(KEY, WireAlgorithm::HmacSha256, &key))).await;
    let dns = Rfc2136Dns::new(&config(server.addr, &key, TsigAlgorithm::HmacSha256)).unwrap();
    dns.present(FQDN, "one").await.unwrap();
    dns.present(FQDN, "two").await.unwrap();
    dns.cleanup(FQDN, "one").await.unwrap();
    assert_eq!(server.txt_values(FQDN), ["two"]);
    let updates: Vec<Message> = server
        .received()
        .into_iter()
        .filter(|m| m.metadata.op_code == OpCode::Update)
        .collect();
    let classes: Vec<DNSClass> = updates
        .iter()
        .flat_map(|m| m.authorities.iter().map(|r| r.dns_class))
        .collect();
    assert_eq!(classes, [DNSClass::IN, DNSClass::IN, DNSClass::NONE]);
    assert!(
        updates.iter().all(|m| m.answers.is_empty()),
        "no prerequisites"
    );
    assert!(
        updates.iter().all(|m| m.signature.is_some()),
        "every update is signed"
    );
    assert!(
        updates
            .iter()
            .all(|m| m.queries[0].name().to_ascii() == "example.com.")
    );
}

#[tokio::test]
async fn signs_with_every_allowed_algorithm() {
    for (ours, wire) in [
        (TsigAlgorithm::HmacSha1, WireAlgorithm::HmacSha1),
        (TsigAlgorithm::HmacSha384, WireAlgorithm::HmacSha384),
        (TsigAlgorithm::HmacSha512, WireAlgorithm::HmacSha512),
    ] {
        let key = secret(4);
        let server = FakeDnsServer::start(Some(ServerKey::new(KEY, wire, &key))).await;
        let dns = Rfc2136Dns::new(&config(server.addr, &key, ours)).unwrap();
        dns.present(FQDN, "v").await.unwrap();
        assert_eq!(server.txt_values(FQDN), ["v"], "{ours:?}");
    }
}

#[test]
fn md5_is_refused_and_a_key_is_required() {
    let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let md5 = Rfc2136Dns::new(&config(addr, &secret(1), TsigAlgorithm::HmacMd5)).unwrap_err();
    assert!(md5.0.contains("hmac-md5 must not be used"), "{md5}");
    let keyless = Rfc2136Provider {
        tsig_key_name: None,
        tsig_secret: None,
        ..config(addr, "", TsigAlgorithm::HmacSha256)
    };
    let error = Rfc2136Dns::new(&keyless).unwrap_err();
    assert!(error.0.contains("insecure_unsigned"), "{error}");
    Rfc2136Dns::new(&Rfc2136Provider {
        insecure_unsigned: true,
        ..keyless
    })
    .unwrap();
}

#[tokio::test]
async fn unsigned_updates_only_when_asked() {
    let server = FakeDnsServer::start(None).await;
    let dns = Rfc2136Dns::new(&Rfc2136Provider {
        tsig_key_name: None,
        tsig_secret: None,
        insecure_unsigned: true,
        ..config(server.addr, "", TsigAlgorithm::HmacSha256)
    })
    .unwrap();
    dns.present(FQDN, "v").await.unwrap();
    assert_eq!(server.txt_values(FQDN), ["v"]);
    assert!(server.received().iter().all(|m| m.signature.is_none()));
}

#[tokio::test]
async fn reports_a_wrong_secret_and_an_unsigned_update() {
    let server = FakeDnsServer::start(Some(ServerKey::new(
        KEY,
        WireAlgorithm::HmacSha256,
        &secret(5),
    )))
    .await;
    let wrong = Rfc2136Dns::new(&config(server.addr, &secret(6), TsigAlgorithm::HmacSha256))
        .unwrap()
        .present(FQDN, "v")
        .await
        .unwrap_err();
    assert!(wrong.0.contains("BADSIG"), "{wrong}");
    assert!(
        !wrong.0.contains(&secret(6)),
        "the secret never appears in errors"
    );
    let unsigned = Rfc2136Dns::new(&Rfc2136Provider {
        tsig_key_name: None,
        tsig_secret: None,
        insecure_unsigned: true,
        ..config(server.addr, "", TsigAlgorithm::HmacSha256)
    })
    .unwrap()
    .present(FQDN, "v")
    .await
    .unwrap_err();
    assert!(
        unsigned.0.contains("REFUSED") || unsigned.0.contains("Refused"),
        "{unsigned}"
    );
    assert_eq!(server.txt_values(FQDN), Vec::<String>::new());
}

#[tokio::test]
async fn the_configured_zone_needs_no_soa_queries() {
    let key = secret(7);
    let server =
        FakeDnsServer::start(Some(ServerKey::new(KEY, WireAlgorithm::HmacSha256, &key))).await;
    let dns = Rfc2136Dns::new(&Rfc2136Provider {
        zone: Some("example.com".into()),
        ..config(server.addr, &key, TsigAlgorithm::HmacSha256)
    })
    .unwrap();
    dns.present(FQDN, "v").await.unwrap();
    assert!(
        server
            .received()
            .iter()
            .all(|m| m.metadata.op_code == OpCode::Update)
    );
}

#[tokio::test]
async fn names_outside_the_servers_zones_are_reported() {
    let key = secret(8);
    let server =
        FakeDnsServer::start(Some(ServerKey::new(KEY, WireAlgorithm::HmacSha256, &key))).await;
    let error = Rfc2136Dns::new(&config(server.addr, &key, TsigAlgorithm::HmacSha256))
        .unwrap()
        .present("_acme-challenge.example.org", "v")
        .await
        .unwrap_err();
    assert!(
        error
            .0
            .contains("to the SOA query for `_acme-challenge.example.org.`; set `zone`"),
        "{error}"
    );
}
