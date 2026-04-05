use aho_corasick::AhoCorasick;

/// Substring matcher using Aho-Corasick automaton.
pub struct SubstringMatcher {
    automaton: Option<AhoCorasick>,
    /// Pattern index -> list indices
    pattern_to_lists: Vec<Vec<usize>>,
}

impl SubstringMatcher {
    pub fn new() -> Self {
        Self {
            automaton: None,
            pattern_to_lists: Vec::new(),
        }
    }

    /// Build from (pattern, list_idx) pairs. Must be called once with all patterns.
    pub fn build(entries: Vec<(String, usize)>) -> Self {
        if entries.is_empty() {
            return Self::new();
        }

        // Deduplicate patterns, accumulating list indices
        let mut pattern_map: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for (pattern, list_idx) in entries {
            pattern_map
                .entry(pattern.to_lowercase())
                .or_default()
                .push(list_idx);
        }

        let mut patterns = Vec::new();
        let mut pattern_to_lists = Vec::new();
        for (pattern, lists) in pattern_map {
            patterns.push(pattern);
            pattern_to_lists.push(lists);
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .ok();

        Self {
            automaton,
            pattern_to_lists,
        }
    }

    pub fn lookup(&self, value: &str) -> Vec<usize> {
        let Some(ref ac) = self.automaton else {
            return Vec::new();
        };

        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();

        for mat in ac.find_iter(value) {
            for &list_idx in &self.pattern_to_lists[mat.pattern().as_usize()] {
                if seen.insert(list_idx) {
                    result.push(list_idx);
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_in_middle() {
        let m = SubstringMatcher::build(vec![("capesandbox.com".into(), 0)]);
        assert_eq!(
            m.lookup("https://capesandbox.com/analysis/12345"),
            vec![0]
        );
    }

    #[test]
    fn substring_is_entire_value() {
        let m = SubstringMatcher::build(vec![("capesandbox.com".into(), 0)]);
        assert_eq!(m.lookup("capesandbox.com"), vec![0]);
    }

    #[test]
    fn no_match() {
        let m = SubstringMatcher::build(vec![("capesandbox.com".into(), 0)]);
        assert!(m.lookup("google.com").is_empty());
    }

    #[test]
    fn overlapping_patterns_different_lists() {
        let m = SubstringMatcher::build(vec![
            ("sandbox".into(), 0),
            ("cape".into(), 1),
        ]);
        let mut result = m.lookup("capesandbox.com");
        result.sort();
        assert_eq!(result, vec![0, 1]);
    }

    #[test]
    fn deduplicates_list_indices() {
        // Pattern appears twice in same value, should only report list once
        let m = SubstringMatcher::build(vec![("ab".into(), 0)]);
        assert_eq!(m.lookup("ababab"), vec![0]);
    }
}
