//! Signing against hickory-proto's own signer, and the checks on answers.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::TSigner;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm as Wire;

use super::*;
use crate::rfc2136::fake_server::{ServerKey, sign_response};

const NOW: u64 = 1_800_000_000;

fn key(secret: &[u8], algorithm: TsigAlgorithm) -> TsigKey {
    TsigKey::new("rdock-acme", &STANDARD.encode(secret), algorithm).unwrap()
}

fn update() -> Message {
    let mut message = Message::query();
    message.metadata.op_code = OpCode::Update;
    message
}

/// The same message signed by hickory's `TSigner` at the same time carries the same MAC.
#[test]
fn signs_like_hickory() {
    let secret = [9u8; 32];
    let mut ours = update();
    let mut theirs = ours.clone();
    let mac = key(&secret, TsigAlgorithm::HmacSha256)
        .resolve()
        .unwrap()
        .sign(&mut ours, NOW)
        .unwrap();
    let signer = TSigner::new(
        secret.to_vec(),
        Wire::HmacSha256,
        Name::from_ascii("rdock-acme.").unwrap(),
        FUDGE,
    )
    .unwrap();
    theirs.finalize(&signer, NOW).unwrap();
    assert_eq!(ours.signature.as_ref().unwrap().data.mac, mac);
    assert_eq!(ours.to_vec().unwrap(), theirs.to_vec().unwrap());
}

/// Signs a request with `secret`, and answers it signed by a server holding `server_secret`.
fn exchange(secret: &[u8], server_secret: &[u8], signed_at: u64) -> (Vec<u8>, Vec<u8>, Message) {
    let mut request = update();
    let mac = key(secret, TsigAlgorithm::HmacSha256)
        .resolve()
        .unwrap()
        .sign(&mut request, NOW)
        .unwrap();
    let server = ServerKey::new(
        "rdock-acme.",
        Wire::HmacSha256,
        &STANDARD.encode(server_secret),
    );
    let response = Message::response(request.metadata.id, OpCode::Update);
    let bytes = sign_response(&server, response, &mac, signed_at);
    let answer = Message::from_vec(&bytes).unwrap();
    (mac, bytes, answer)
}

#[test]
fn verifies_the_servers_signature() {
    let key = key(&[1; 32], TsigAlgorithm::HmacSha256);
    let signing = key.resolve().unwrap();
    let (mac, bytes, answer) = exchange(&[1; 32], &[1; 32], NOW);
    signing.verify(&answer, &bytes, &mac, NOW).unwrap();

    let (mac, bytes, answer) = exchange(&[1; 32], &[2; 32], NOW);
    let forged = signing.verify(&answer, &bytes, &mac, NOW).unwrap_err();
    assert!(forged.contains("does not match"), "{forged}");

    let (mac, bytes, answer) = exchange(&[1; 32], &[1; 32], NOW - 3600);
    let stale = signing.verify(&answer, &bytes, &mac, NOW).unwrap_err();
    assert!(stale.contains("check the clocks"), "{stale}");
}

#[test]
fn unsigned_answers_pass_only_as_errors() {
    let signing = key(&[1; 32], TsigAlgorithm::HmacSha256);
    let signing = signing.resolve().unwrap();
    let success = Message::response(1, OpCode::Update);
    let error = signing
        .verify(&success, &success.to_vec().unwrap(), b"mac", NOW)
        .unwrap_err();
    assert!(error.contains("not signed"), "{error}");
    let refused = Message::error_msg(1, OpCode::Update, ResponseCode::Refused);
    signing
        .verify(&refused, &refused.to_vec().unwrap(), b"mac", NOW)
        .unwrap();
}

#[test]
fn secrets_must_be_base64() {
    let key = TsigKey::new("k", "not base64!", TsigAlgorithm::HmacSha256).unwrap();
    let error = key.resolve().err().unwrap();
    assert_eq!(error.0, "tsig_secret is not base64");
}
