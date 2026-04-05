use std::collections::HashMap;

/// Exact (case-insensitive) string matcher.
pub struct StringMatcher {
    /// Lowercased value -> list of warninglist indices that contain it.
    map: HashMap<String, Vec<usize>>,
}

impl StringMatcher {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn add_entries(&mut self, entries: &[String], list_idx: usize) {
        for entry in entries {
            self.map
                .entry(entry.to_lowercase())
                .or_default()
                .push(list_idx);
        }
    }

    pub fn lookup(&self, value: &str) -> Vec<usize> {
        self.map
            .get(&value.to_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let mut m = StringMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert_eq!(m.lookup("google.com"), vec![0]);
    }

    #[test]
    fn case_insensitive() {
        let mut m = StringMatcher::new();
        m.add_entries(&["Google.COM".into()], 0);
        assert_eq!(m.lookup("google.com"), vec![0]);
        assert_eq!(m.lookup("GOOGLE.COM"), vec![0]);
    }

    #[test]
    fn miss_returns_empty() {
        let mut m = StringMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert!(m.lookup("notfound.com").is_empty());
    }

    #[test]
    fn multiple_lists_same_entry() {
        let mut m = StringMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        m.add_entries(&["google.com".into()], 1);
        let mut result = m.lookup("google.com");
        result.sort();
        assert_eq!(result, vec![0, 1]);
    }
}
