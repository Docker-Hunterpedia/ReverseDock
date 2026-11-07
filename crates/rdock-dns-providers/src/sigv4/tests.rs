//! The signer against the worked examples AWS publishes with their expected signatures, in
//! "Examples: Signature Calculations" of
//! <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html>
//! (checked 2026-11-07): access key `AKIAIOSFODNN7EXAMPLE`, secret
//! `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, 2013-05-24 00:00:00 UTC, `us-east-1`, `s3`.
//! S3 encodes paths once where other services encode them twice; the Route 53 paths we sign
//! hold only unreserved characters, for which both are the same.

use super::*;

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn example_key() -> AwsKey {
    AwsKey {
        access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
        session_token: None,
    }
}

fn s3() -> Scope<'static> {
    Scope {
        region: "us-east-1",
        service: "s3",
    }
}

fn may_24_2013() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_369_353_600).unwrap()
}

fn signed(mut request: Request<Bytes>) -> (Request<Bytes>, String) {
    sign(&mut request, &example_key(), &s3(), may_24_2013()).unwrap();
    let authorization = request.headers()["authorization"]
        .to_str()
        .unwrap()
        .to_owned();
    (request, authorization)
}

fn signature(authorization: &str) -> &str {
    authorization.rsplit("Signature=").next().unwrap()
}

#[test]
fn get_object_example() {
    let request = Request::get("https://examplebucket.s3.amazonaws.com/test.txt")
        .header("range", "bytes=0-9 ")
        .header("x-amz-content-sha256", EMPTY_SHA256)
        .body(Bytes::new())
        .unwrap();
    let (request, authorization) = signed(request);
    let (canonical, signed_headers) = canonical_request(&request);
    assert_eq!(
        canonical,
        format!(
            "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}"
        )
    );
    assert_eq!(
        string_to_sign(
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            &canonical
        ),
        "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
    );
    assert_eq!(signed_headers, "host;range;x-amz-content-sha256;x-amz-date");
    assert_eq!(
        authorization,
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn put_object_example_signs_the_payload() {
    let request = Request::put("https://examplebucket.s3.amazonaws.com/test%24file.text")
        .header("date", "Fri, 24 May 2013 00:00:00 GMT")
        .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
        .header(
            "x-amz-content-sha256",
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
        )
        .body(Bytes::from_static(b"Welcome to Amazon S3."))
        .unwrap();
    let (_, authorization) = signed(request);
    assert_eq!(
        signature(&authorization),
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    );
}

#[test]
fn list_objects_example_sorts_the_query() {
    let request = Request::get("https://examplebucket.s3.amazonaws.com/?prefix=J&max-keys=2")
        .header("x-amz-content-sha256", EMPTY_SHA256)
        .body(Bytes::new())
        .unwrap();
    let (request, authorization) = signed(request);
    assert!(
        canonical_request(&request)
            .0
            .starts_with("GET\n/\nmax-keys=2&prefix=J\n")
    );
    assert_eq!(
        signature(&authorization),
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    );
}

#[test]
fn session_tokens_are_sent_and_signed() {
    let mut key = example_key();
    key.session_token = Some("FQoGZXIvYXdzEXAMPLE".to_owned());
    let mut request = Request::get("https://route53.amazonaws.com/2013-04-01/change/C1")
        .body(Bytes::new())
        .unwrap();
    let scope = Scope {
        region: "us-east-1",
        service: "route53",
    };
    sign(&mut request, &key, &scope, may_24_2013()).unwrap();
    assert_eq!(
        request.headers()["x-amz-security-token"],
        "FQoGZXIvYXdzEXAMPLE"
    );
    let authorization = request.headers()["authorization"].to_str().unwrap();
    assert!(
        authorization.contains(
            "/20130524/us-east-1/route53/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token,"
        ),
        "{authorization}"
    );
}

#[test]
fn queries_are_encoded_like_uri_encode() {
    assert_eq!(
        canonical_query("name=_acme-challenge.example.com&type=TXT&a=x%2By+z"),
        "a=x%2By%2Bz&name=_acme-challenge.example.com&type=TXT"
    );
    assert_eq!(canonical_query("acl"), "acl=");
}
