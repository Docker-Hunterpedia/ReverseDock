use std::collections::BTreeMap;

use rdock_model::gateway::{ApiKeyEntry, Consumer as ConsumerConfig};

use super::*;
use crate::test_support::{block_on, cx, reply_header, request};

struct Fixture {
    key: String,
    expired: String,
    id: String,
    index: Arc<ConsumerIndex>,
}

fn fixture() -> Fixture {
    let key = rdock_credentials::API_KEY.generate().unwrap();
    let old = rdock_credentials::API_KEY.generate().unwrap();
    let mut consumers = BTreeMap::new();
    consumers.insert(
        "acme".to_owned(),
        ConsumerConfig {
            group_list: Some(vec!["gold".into(), "eu".into()]),
            keys: vec![
                ApiKeyEntry {
                    id: key.id.clone(),
                    hash: key.secret_sha256.clone(),
                    expires: Some("2999-01-01T00:00:00Z".into()),
                    note: None,
                },
                ApiKeyEntry {
                    id: old.id.clone(),
                    hash: old.secret_sha256.clone(),
                    expires: Some("2020-01-01T00:00:00Z".into()),
                    note: None,
                },
            ],
            keys_file: None,
        },
    );
    Fixture {
        id: key.id.clone(),
        key: key.value.into_inner(),
        expired: old.value.into_inner(),
        index: Arc::new(ConsumerIndex::build(&consumers).unwrap()),
    }
}

fn middleware(f: &Fixture, config: &ApiKeyConfig) -> ApiKey {
    ApiKey::new("keys", config, f.index.clone()).unwrap()
}

#[test]
fn a_valid_key_sets_the_consumer_and_leaves_the_request() {
    let f = fixture();
    let mw = middleware(&f, &ApiKeyConfig::default());
    for (header, value) in [
        ("authorization", format!("Bearer {}", f.key)),
        ("x-api-key", f.key.clone()),
    ] {
        let mut req = request(
            "GET",
            "/",
            &[(header, value.as_str()), ("x-consumer-name", "admin")],
        );
        let mut cx = cx();
        assert_eq!(block_on(mw.request(&mut req, &mut cx)), Flow::Next);
        let consumer = cx.consumer.unwrap();
        assert_eq!(&*consumer.name, "acme");
        assert_eq!(cx.key_id.as_deref(), Some(f.id.as_str()));
        assert!(
            req.headers.get(header).is_none(),
            "the key is not forwarded"
        );
        assert_eq!(req.headers.get("x-consumer-name").unwrap(), "acme");
        assert_eq!(req.headers.get("x-consumer-groups").unwrap(), "gold,eu");
        assert_eq!(req.headers.get("x-credential-id").unwrap(), f.id.as_str());
    }
}

#[test]
fn missing_malformed_wrong_and_expired_keys_are_refused() {
    let f = fixture();
    let mw = middleware(&f, &ApiKeyConfig::default());
    let refuse = |headers: &[(&'static str, &str)]| {
        let mut req = request("GET", "/", headers);
        let mut cx = cx();
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx)) else {
            panic!("refused")
        };
        assert!(cx.consumer.is_none());
        reply
    };
    let missing = refuse(&[]);
    assert_eq!(missing.status, 401);
    assert_eq!(
        reply_header(&missing, "www-authenticate"),
        Some("Bearer realm=\"api\"")
    );
    // Basic credentials are another middleware's business, not a key.
    assert_eq!(refuse(&[("authorization", "Basic dTpw")]).status, 401);
    let mut typo = f.key.clone().into_bytes();
    typo[20] = if typo[20] == b'x' { b'y' } else { b'x' };
    let typo = String::from_utf8(typo).unwrap();
    let invalid = refuse(&[("x-api-key", &typo)]);
    assert_eq!(
        reply_header(&invalid, "www-authenticate"),
        Some("Bearer realm=\"api\", error=\"invalid_token\"")
    );
    // A well-formed key with a correct checksum that nobody owns.
    let stranger = rdock_credentials::API_KEY.generate().unwrap();
    assert_eq!(
        refuse(&[("x-api-key", stranger.value.expose())]).status,
        401
    );
    // The right ID with another secret (and a recomputed checksum).
    let (id, _) = rdock_credentials::API_KEY.parse(&f.key).unwrap();
    let body = format!("rdk_{id}_{}", "A".repeat(32));
    let forged = format!("{body}{}", rdock_credentials::checksum(&body));
    assert_eq!(refuse(&[("x-api-key", &forged)]).status, 401);
    assert_eq!(refuse(&[("x-api-key", &f.expired)]).status, 401);
    // Two keys: the backend could read the other one.
    let mut req = request("GET", "/", &[("x-api-key", &f.key)]);
    req.append_header("x-api-key", f.key.as_str()).unwrap();
    let Flow::Reply(repeated) = block_on(mw.request(&mut req, &mut cx())) else {
        panic!("refused")
    };
    assert_eq!(repeated.status, 400);
}

#[test]
fn query_keys_only_when_named_anonymous_and_groups() {
    let f = fixture();
    let mw = middleware(&f, &ApiKeyConfig::default());
    let target = format!("/x?api_key={}&a=1", f.key);
    let Flow::Reply(reply) = block_on(mw.request(&mut request("GET", &target, &[]), &mut cx()))
    else {
        panic!("no query keys by default")
    };
    assert_eq!(reply.status, 401);

    let by_query = middleware(
        &f,
        &ApiKeyConfig {
            query: Some("api_key".into()),
            ..ApiKeyConfig::default()
        },
    );
    let mut req = request("GET", &target, &[]);
    assert_eq!(block_on(by_query.request(&mut req, &mut cx())), Flow::Next);
    assert_eq!(
        req.uri.to_string(),
        "/x?a=1",
        "the key is removed from the URL"
    );

    let anonymous = middleware(
        &f,
        &ApiKeyConfig {
            anonymous: Anonymous::Allow,
            ..ApiKeyConfig::default()
        },
    );
    let mut cx_anon = cx();
    assert_eq!(
        block_on(anonymous.request(&mut request("GET", "/", &[]), &mut cx_anon)),
        Flow::Next
    );
    assert!(cx_anon.consumer.is_none());
    let Flow::Reply(bad) = block_on(anonymous.request(
        &mut request("GET", "/", &[("x-api-key", "rdk_nope")]),
        &mut cx(),
    )) else {
        panic!("an invalid key is refused even when anonymous requests are allowed")
    };
    assert_eq!(bad.status, 401);

    let platinum = middleware(
        &f,
        &ApiKeyConfig {
            groups: vec!["platinum".into()],
            forward_credential: true,
            ..ApiKeyConfig::default()
        },
    );
    let Flow::Reply(forbidden) = block_on(platinum.request(
        &mut request("GET", "/", &[("x-api-key", &f.key)]),
        &mut cx(),
    )) else {
        panic!("not in the group")
    };
    assert_eq!(forbidden.status, 403);
    let gold = middleware(
        &f,
        &ApiKeyConfig {
            groups: vec!["eu".into()],
            forward_credential: true,
            ..ApiKeyConfig::default()
        },
    );
    let mut req = request("GET", "/", &[("x-api-key", &f.key)]);
    assert_eq!(block_on(gold.request(&mut req, &mut cx())), Flow::Next);
    assert!(
        req.headers.get("x-api-key").is_some(),
        "forward_credential keeps it"
    );
}

/// L4 of the v0.8 review: with `forward_credential: false` no configured location keeps a key
/// for the backend, the query parameter's name is matched decoded, and a second, different
/// key elsewhere is refused like a repeated one.
#[test]
fn every_copy_of_the_key_is_removed_and_a_second_key_is_refused() {
    let f = fixture();
    let mw = middleware(
        &f,
        &ApiKeyConfig {
            query: Some("api_key".into()),
            ..ApiKeyConfig::default()
        },
    );
    // The same key in a header, the other header and the query (name percent-encoded).
    let bearer = format!("Bearer {}", f.key);
    let target = format!("/x?%61pi_key={}&a=1", f.key);
    let mut req = request(
        "GET",
        &target,
        &[("authorization", &bearer), ("x-api-key", &f.key)],
    );
    assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
    assert!(req.headers.get("authorization").is_none());
    assert!(req.headers.get("x-api-key").is_none());
    assert_eq!(req.uri.to_string(), "/x?a=1");

    // A value that is not a key in another configured header is not ours and stays.
    let mut req = request(
        "GET",
        "/",
        &[("authorization", &bearer), ("x-api-key", "not-a-key")],
    );
    assert_eq!(block_on(mw.request(&mut req, &mut cx())), Flow::Next);
    assert_eq!(req.headers.get("x-api-key").unwrap(), "not-a-key");

    // A different key in another location: 400, whichever location comes first.
    for (headers, target) in [
        (
            vec![
                ("authorization", bearer.clone()),
                ("x-api-key", f.expired.clone()),
            ],
            "/".to_owned(),
        ),
        (
            vec![("x-api-key", f.key.clone())],
            format!("/?api_key={}", f.expired),
        ),
        (vec![], format!("/?api_key={}&%61pi_key={}", f.key, f.key)),
    ] {
        let headers: Vec<(&'static str, &str)> =
            headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let mut req = request("GET", &target, &headers);
        let Flow::Reply(reply) = block_on(mw.request(&mut req, &mut cx())) else {
            panic!("two keys: {headers:?} {target}")
        };
        assert_eq!(reply.status, 400, "{headers:?} {target}");
    }
}
