/// "Did you mean" helper used across ReverseDock: returns the candidate closest to `input`, an
/// exact case-insensitive match first, otherwise the nearest one within an edit distance of 2.
pub fn closest_match<'a>(
    input: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    let candidates: Vec<&str> = candidates.into_iter().collect();
    if let Some(exact) = candidates.iter().find(|c| c.eq_ignore_ascii_case(input)) {
        return Some(exact);
    }
    let lower = input.to_ascii_lowercase();
    candidates
        .into_iter()
        .map(|c| (levenshtein(&lower, &c.to_ascii_lowercase()), c))
        .filter(|(distance, _)| *distance <= 2)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, c)| c)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut current = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(ca != *cb);
            current.push(substitution.min(previous[j + 1] + 1).min(current[j] + 1));
        }
        previous = current;
    }
    previous[b.len()]
}

#[cfg(test)]
mod tests {
    use super::closest_match;

    #[test]
    fn prefers_case_insensitive_match_then_small_edits() {
        let names = ["Host", "HostRegexp", "Path"];
        assert_eq!(closest_match("host", names), Some("Host"));
        assert_eq!(closest_match("Hots", names), Some("Host"));
        assert_eq!(closest_match("Whatever", names), None);
    }
}
