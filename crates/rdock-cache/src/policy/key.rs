//! The cache key: every component that selects a response, framed so two different sets of
//! components can never produce the same bytes (pingora-cache hashes the result with
//! BLAKE2b-128 and asks callers to frame components unambiguously; CVE-2026-2836 was a key
//! that held the path only).

/// The components of a primary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyParts<'a> {
    /// Store name.
    pub store: &'a str,
    /// Route name: two routes never share objects, even in one store.
    pub route: &'a str,
    /// `http` or `https`, as the client asked.
    pub scheme: &'a str,
    /// Host, lower case, without the port.
    pub host: &'a str,
    /// Path as forwarded to the origin (after normalisation and the route's rewrites).
    pub path: &'a str,
    /// Query after the route's `key.query` rule.
    pub query: &'a str,
    /// `GET` for both `GET` and `HEAD`.
    pub method: &'a str,
    /// `key.headers`: each name with its normalised value, or `None` when absent.
    pub headers: &'a [(&'a str, Option<&'a [u8]>)],
    /// `key.consumer`: the authenticated identity (`None` when not keyed).
    pub consumer: Option<&'a str>,
}

/// Field tags of the framing; each component is `tag, u32 length (big endian), bytes`.
mod tag {
    pub const VERSION: u8 = 0;
    pub const STORE: u8 = 1;
    pub const ROUTE: u8 = 2;
    pub const SCHEME: u8 = 3;
    pub const HOST: u8 = 4;
    pub const PATH: u8 = 5;
    pub const QUERY: u8 = 6;
    pub const METHOD: u8 = 7;
    pub const HEADER_NAME: u8 = 8;
    pub const HEADER_VALUE: u8 = 9;
    pub const HEADER_ABSENT: u8 = 10;
    pub const CONSUMER: u8 = 11;
}

/// The framing version; changing the layout changes it, so old objects are never matched.
const VERSION: &[u8] = b"rdock-key-1";

fn push(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The framed primary key.
#[must_use]
pub fn primary(parts: &KeyParts<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        64 + parts.store.len()
            + parts.route.len()
            + parts.host.len()
            + parts.path.len()
            + parts.query.len(),
    );
    push(&mut out, tag::VERSION, VERSION);
    push(&mut out, tag::STORE, parts.store.as_bytes());
    push(&mut out, tag::ROUTE, parts.route.as_bytes());
    push(&mut out, tag::SCHEME, parts.scheme.as_bytes());
    push(&mut out, tag::HOST, parts.host.as_bytes());
    push(&mut out, tag::PATH, parts.path.as_bytes());
    push(&mut out, tag::QUERY, parts.query.as_bytes());
    push(&mut out, tag::METHOD, parts.method.as_bytes());
    for (name, value) in parts.headers {
        push(&mut out, tag::HEADER_NAME, name.as_bytes());
        match value {
            Some(v) => push(&mut out, tag::HEADER_VALUE, v),
            None => push(&mut out, tag::HEADER_ABSENT, b""),
        }
    }
    if let Some(consumer) = parts.consumer {
        push(&mut out, tag::CONSUMER, consumer.as_bytes());
    }
    out
}

/// The method class of the key: `HEAD` is answered from a stored `GET`.
#[must_use]
pub fn method_class(method: &http::Method) -> &'static str {
    if *method == http::Method::GET || *method == http::Method::HEAD {
        "GET"
    } else {
        "OTHER"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parts<'a>(
        strings: &'a [String; 7],
        headers: &'a [(&'a str, Option<&'a [u8]>)],
        consumer: Option<&'a str>,
    ) -> KeyParts<'a> {
        KeyParts {
            store: &strings[0],
            route: &strings[1],
            scheme: &strings[2],
            host: &strings[3],
            path: &strings[4],
            query: &strings[5],
            method: &strings[6],
            headers,
            consumer,
        }
    }

    #[test]
    fn components_cannot_bleed_into_each_other() {
        let a = ["s", "r", "https", "a.test", "/x", "q=1", "GET"].map(String::from);
        let b = ["s", "r", "https", "a.test/", "x", "q=1", "GET"].map(String::from);
        assert_ne!(
            primary(&parts(&a, &[], None)),
            primary(&parts(&b, &[], None))
        );
        // An absent header differs from an empty one, and from no header at all.
        let absent = [("x-a", None)];
        let empty = [("x-a", Some(b"".as_slice()))];
        let k1 = primary(&parts(&a, &absent, None));
        let k2 = primary(&parts(&a, &empty, None));
        let k3 = primary(&parts(&a, &[], None));
        assert!(k1 != k2 && k1 != k3 && k2 != k3);
        assert_ne!(primary(&parts(&a, &[], Some("alice"))), k3);
        assert_eq!(method_class(&http::Method::HEAD), "GET");
    }

    proptest! {
        /// The framing is injective: different component tuples give different keys.
        #[test]
        fn framing_is_injective(
            x in proptest::array::uniform7("[a-c/=?&]{0,4}"),
            y in proptest::array::uniform7("[a-c/=?&]{0,4}"),
            hx in proptest::option::of("[a-c]{0,3}"),
            hy in proptest::option::of("[a-c]{0,3}"),
            cx in proptest::option::of("[a-c]{0,3}"),
            cy in proptest::option::of("[a-c]{0,3}"),
        ) {
            let headers_x = [("h", hx.as_deref().map(str::as_bytes))];
            let headers_y = [("h", hy.as_deref().map(str::as_bytes))];
            let kx = primary(&parts(&x, &headers_x, cx.as_deref()));
            let ky = primary(&parts(&y, &headers_y, cy.as_deref()));
            let same = x == y && hx == hy && cx == cy;
            prop_assert_eq!(kx == ky, same);
        }
    }
}
