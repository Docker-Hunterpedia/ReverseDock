//! Cache tags from response headers (`Cache-Tag`, comma-separated; `Surrogate-Key`,
//! space-separated), for purging groups of objects.

use http::HeaderMap;
use http::header::HeaderName;

/// Longest tag kept (Cloudflare's limit for a tag in a purge call).
pub const MAX_TAG_LEN: usize = 1024;
/// Most tags kept per object; further ones are ignored.
pub const MAX_TAGS: usize = 64;

/// The tags in the headers `names` of a response: split on commas and whitespace, lower
/// case, printable ASCII only, at most [`MAX_TAGS`] of at most [`MAX_TAG_LEN`] bytes, without
/// duplicates.
#[must_use]
pub fn parse_tags(headers: &HeaderMap, names: &[HeaderName]) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for name in names {
        for value in headers.get_all(name) {
            let Ok(text) = value.to_str() else {
                continue;
            };
            for tag in text.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
                if tag.is_empty()
                    || tag.len() > MAX_TAG_LEN
                    || !tag.bytes().all(|b| b.is_ascii_graphic())
                {
                    continue;
                }
                let tag = tag.to_ascii_lowercase();
                if !tags.contains(&tag) {
                    if tags.len() == MAX_TAGS {
                        return tags;
                    }
                    tags.push(tag);
                }
            }
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_tag_and_surrogate_key_are_split_lowercased_and_bounded() {
        let mut h = HeaderMap::new();
        h.append("cache-tag", "Product-1, list ,product-1".parse().unwrap());
        h.append("surrogate-key", "k1 k2\tk3".parse().unwrap());
        h.append("cache-tag", "x".repeat(MAX_TAG_LEN + 1).parse().unwrap());
        let names = [
            HeaderName::from_static("cache-tag"),
            HeaderName::from_static("surrogate-key"),
        ];
        assert_eq!(
            parse_tags(&h, &names),
            ["product-1", "list", "k1", "k2", "k3"]
        );
        let mut many = HeaderMap::new();
        let list: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
        many.insert("cache-tag", list.join(",").parse().unwrap());
        assert_eq!(parse_tags(&many, &names[..1]).len(), MAX_TAGS);
    }
}
