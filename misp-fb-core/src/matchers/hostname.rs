use std::collections::HashMap;

/// Reversed-label trie for hostname matching.
/// Supports exact match and subdomain match.
/// Leading dot entries (`.example.com`) match subdomains only.
/// Non-dot entries (`example.com`) match exact and subdomains.
pub struct HostnameMatcher {
    root: TrieNode,
}

#[derive(Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// Lists that match this exact hostname.
    exact_matches: Vec<usize>,
    /// Lists that match any subdomain of this hostname.
    subdomain_matches: Vec<usize>,
}

impl HostnameMatcher {
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    pub fn add_entries(&mut self, entries: &[String], list_idx: usize) {
        for entry in entries {
            let entry_lower = entry.to_lowercase();
            let (hostname, subdomain_only) = if let Some(stripped) = entry_lower.strip_prefix('.') {
                (stripped, true)
            } else {
                (entry_lower.as_str(), false)
            };

            let labels: Vec<&str> = hostname.split('.').rev().collect();
            let mut node = &mut self.root;

            for label in &labels {
                node = node.children.entry((*label).to_string()).or_default();
            }

            if subdomain_only {
                node.subdomain_matches.push(list_idx);
            } else {
                node.exact_matches.push(list_idx);
                node.subdomain_matches.push(list_idx);
            }
        }
    }

    pub fn lookup(&self, value: &str) -> Vec<usize> {
        let value_lower = value.to_lowercase();
        let labels: Vec<&str> = value_lower.split('.').rev().collect();
        let mut result = Vec::new();
        let mut node = &self.root;

        for (i, label) in labels.iter().enumerate() {
            match node.children.get(*label) {
                Some(child) => {
                    let is_last = i == labels.len() - 1;
                    if is_last {
                        // Exact match at terminal node
                        result.extend(&child.exact_matches);
                    } else {
                        // Still have more labels — this is a subdomain
                        result.extend(&child.subdomain_matches);
                    }
                    node = child;
                }
                None => break,
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_match() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert_eq!(m.lookup("google.com"), vec![0]);
    }

    #[test]
    fn subdomain_match() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert_eq!(m.lookup("mail.google.com"), vec![0]);
    }

    #[test]
    fn deeply_nested_subdomain() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert_eq!(m.lookup("a.b.c.google.com"), vec![0]);
    }

    #[test]
    fn leading_dot_subdomain_only() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&[".amazonaws.com".into()], 0);
        // Subdomain matches
        assert_eq!(m.lookup("s3.amazonaws.com"), vec![0]);
        // Exact does NOT match (leading dot = subdomain only)
        assert!(m.lookup("amazonaws.com").is_empty());
    }

    #[test]
    fn no_match() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        assert!(m.lookup("example.com").is_empty());
    }

    #[test]
    fn case_insensitive() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["Google.COM".into()], 0);
        assert_eq!(m.lookup("google.com"), vec![0]);
        assert_eq!(m.lookup("MAIL.GOOGLE.COM"), vec![0]);
    }

    #[test]
    fn multiple_lists() {
        let mut m = HostnameMatcher::new();
        m.add_entries(&["google.com".into()], 0);
        m.add_entries(&["google.com".into()], 1);
        let mut result = m.lookup("google.com");
        result.sort();
        assert_eq!(result, vec![0, 1]);
    }
}
