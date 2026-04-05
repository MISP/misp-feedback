use regex::RegexSet;

/// Regex matcher using compiled RegexSet.
pub struct RegexMatcher {
    regex_set: Option<RegexSet>,
    /// Pattern index -> list indices
    pattern_to_lists: Vec<Vec<usize>>,
}

/// Parse JavaScript-style `/pattern/flags` into a Rust regex string.
/// `/^foo$/i` -> `(?i)^foo$`
/// Bare patterns (no slashes) are returned as-is.
fn parse_js_regex(raw: &str) -> String {
    let raw = raw.trim();

    // Check for /pattern/flags format
    if raw.starts_with('/') {
        if let Some(last_slash) = raw.rfind('/') {
            if last_slash > 0 {
                let pattern = &raw[1..last_slash];
                let flags = &raw[last_slash + 1..];

                let mut prefix = String::new();
                for flag in flags.chars() {
                    match flag {
                        'i' => prefix.push_str("(?i)"),
                        // 'g' and 'm' and others are ignored or handled differently
                        'm' => prefix.push_str("(?m)"),
                        _ => {} // ignore unknown flags like 'g'
                    }
                }

                return format!("{}{}", prefix, pattern);
            }
        }
    }

    raw.to_string()
}

impl RegexMatcher {
    pub fn new() -> Self {
        Self {
            regex_set: None,
            pattern_to_lists: Vec::new(),
        }
    }

    /// Build from (raw_pattern, list_idx) pairs.
    pub fn build(entries: Vec<(String, usize)>) -> Self {
        if entries.is_empty() {
            return Self::new();
        }

        let mut patterns = Vec::new();
        let mut pattern_to_lists = Vec::new();

        for (raw, list_idx) in entries {
            let parsed = parse_js_regex(&raw);
            patterns.push(parsed);
            pattern_to_lists.push(vec![list_idx]);
        }

        match RegexSet::new(&patterns) {
            Ok(regex_set) => Self {
                regex_set: Some(regex_set),
                pattern_to_lists,
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to compile regex set");
                Self::new()
            }
        }
    }

    pub fn lookup(&self, value: &str) -> Vec<usize> {
        let Some(ref rs) = self.regex_set else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for idx in rs.matches(value) {
            result.extend(&self.pattern_to_lists[idx]);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_js_regex_with_flags() {
        assert_eq!(
            parse_js_regex(r"/^(security|noc|soc|abuse)\@.*\..*$/i"),
            r"(?i)^(security|noc|soc|abuse)\@.*\..*$"
        );
    }

    #[test]
    fn parse_js_regex_no_flags() {
        assert_eq!(parse_js_regex(r"/^foo$/"), r"^foo$");
    }

    #[test]
    fn parse_bare_pattern() {
        assert_eq!(parse_js_regex(r"^foo$"), r"^foo$");
    }

    #[test]
    fn parse_js_regex_g_flag_ignored() {
        assert_eq!(parse_js_regex(r"/pattern/g"), "pattern");
    }

    #[test]
    fn regex_email_match() {
        let m = RegexMatcher::build(vec![(
            r"/^(security|noc|soc|abuse)\@.*\..*$/i".into(),
            0,
        )]);
        assert_eq!(m.lookup("abuse@example.com"), vec![0]);
        assert_eq!(m.lookup("security@test.org"), vec![0]);
    }

    #[test]
    fn regex_no_match() {
        let m = RegexMatcher::build(vec![(
            r"/^(security|noc|soc|abuse)\@.*\..*$/i".into(),
            0,
        )]);
        assert!(m.lookup("hello@example.com").is_empty());
    }

    #[test]
    fn empty_matcher() {
        let m = RegexMatcher::build(vec![]);
        assert!(m.lookup("anything").is_empty());
    }
}
