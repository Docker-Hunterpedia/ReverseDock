//! Just enough XML for the Route 53 API. Its answers are small documents of a known shape: no
//! attributes are read, no CDATA, no element nested in one of its own name, so a careful
//! extractor does the job without a parser dependency; requests are written with [`escape`].

/// The content of every `<tag>…</tag>` element in `xml`, in document order, as written (it may
/// hold child elements). `<tag/>` has empty content.
pub(crate) fn elements<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end_of_tag) = after.find('>') else {
            break;
        };
        let head = &after[..end_of_tag];
        let content = &after[end_of_tag + 1..];
        if !(head.is_empty() || head.starts_with(|c: char| c.is_whitespace() || c == '/')) {
            // A longer name with the same start, such as `<HostedZones>` for `HostedZone`.
            rest = after;
            continue;
        }
        if head.ends_with('/') {
            found.push("");
            rest = content;
            continue;
        }
        let Some(end) = content.find(&close) else {
            break;
        };
        found.push(&content[..end]);
        rest = &content[end + close.len()..];
    }
    found
}

/// The text of the first `<tag>` element, unescaped.
pub(crate) fn text(xml: &str, tag: &str) -> Option<String> {
    elements(xml, tag)
        .first()
        .and_then(|content| unescape(content))
}

/// `text` with the five predefined entities written as references.
pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Character data with its entity and character references resolved; `None` when a reference
/// is malformed or the text holds markup.
pub(crate) fn unescape(text: &str) -> Option<String> {
    if text.contains('<') {
        return None;
    }
    let mut plain = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        plain.push_str(&rest[..amp]);
        let reference = &rest[amp + 1..];
        let end = reference.find(';')?;
        plain.push(match &reference[..end] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            code => {
                let number = match code.strip_prefix("#x") {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => code.strip_prefix('#')?.parse().ok()?,
                };
                char::from_u32(number)?
            }
        });
        rest = &reference[end + 1..];
    }
    plain.push_str(rest);
    Some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_elements_without_confusing_longer_names() {
        let xml = r#"<?xml version="1.0"?><R xmlns="x"><HostedZones><HostedZone><Id>/hostedzone/Z1</Id><Config><PrivateZone>true</PrivateZone></Config></HostedZone><HostedZone><Id>/hostedzone/Z2</Id><Config/></HostedZone></HostedZones></R>"#;
        let zones = elements(xml, "HostedZone");
        assert_eq!(zones.len(), 2);
        assert_eq!(text(zones[0], "Id").as_deref(), Some("/hostedzone/Z1"));
        assert_eq!(text(zones[0], "PrivateZone").as_deref(), Some("true"));
        assert_eq!(elements(zones[1], "Config"), [""]);
        assert_eq!(text(zones[1], "PrivateZone"), None);
    }

    #[test]
    fn references_round_trip() {
        let value = r#""a&b" <c> 'd'"#;
        assert_eq!(unescape(&escape(value)).as_deref(), Some(value));
        assert_eq!(unescape("&#34;x&#x22;").as_deref(), Some("\"x\""));
        assert_eq!(unescape("&bogus;"), None);
        assert_eq!(unescape("a & b"), None);
        assert_eq!(unescape("<b>x</b>"), None);
    }
}
