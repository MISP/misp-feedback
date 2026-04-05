use std::path::Path;

use crate::error::{Error, Result};
use crate::model::RawWarningList;

/// Load warninglists from a directory, applying the given slug filter.
/// Returns (slug, RawWarningList) pairs sorted by slug.
/// Skips empty lists and logs parse errors as warnings.
pub fn load_warninglists(
    lists_dir: &Path,
    filter: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, RawWarningList)>> {
    let mut entries: Vec<_> = std::fs::read_dir(lists_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    entries.sort_by_key(|e| e.file_name());

    let mut result = Vec::new();

    for entry in entries {
        let slug = entry.file_name().to_string_lossy().to_string();

        if !filter(&slug) {
            continue;
        }

        let list_path = entry.path().join("list.json");
        if !list_path.exists() {
            tracing::warn!(slug = %slug, "No list.json found, skipping");
            continue;
        }

        let content = match std::fs::read_to_string(&list_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(slug = %slug, error = %e, "Failed to read list.json, skipping");
                continue;
            }
        };

        let raw: RawWarningList = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(slug = %slug, error = %e, "Failed to parse list.json, skipping");
                return Err(Error::JsonParse {
                    path: list_path.display().to_string(),
                    source: e,
                });
            }
        };

        if raw.list.is_empty() {
            tracing::warn!(slug = %slug, name = %raw.name, "Empty list, skipping");
            continue;
        }

        result.push((slug, raw));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn lists_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("misp-warninglists/lists")
    }

    #[test]
    fn load_all_lists() {
        let lists = load_warninglists(&lists_dir(), &|_| true).unwrap();
        // 122 total minus 2 empty (crl-ip, crl-hostname)
        assert!(lists.len() >= 100, "Expected 100+ lists, got {}", lists.len());
        // Verify sorted by slug
        for w in lists.windows(2) {
            assert!(w[0].0 <= w[1].0, "Not sorted: {} > {}", w[0].0, w[1].0);
        }
    }

    #[test]
    fn load_with_include_filter() {
        let lists = load_warninglists(&lists_dir(), &|slug| {
            slug == "amazon-aws" || slug == "cloudflare"
        })
        .unwrap();
        assert_eq!(lists.len(), 2);
        assert!(lists.iter().any(|(s, _)| s == "amazon-aws"));
        assert!(lists.iter().any(|(s, _)| s == "cloudflare"));
    }

    #[test]
    fn load_with_exclude_filter() {
        let all = load_warninglists(&lists_dir(), &|_| true).unwrap();
        let filtered = load_warninglists(&lists_dir(), &|slug| slug != "alexa").unwrap();
        assert_eq!(filtered.len(), all.len() - 1);
        assert!(!filtered.iter().any(|(s, _)| s == "alexa"));
    }

    #[test]
    fn empty_lists_are_skipped() {
        let lists = load_warninglists(&lists_dir(), &|slug| {
            slug == "crl-ip" || slug == "crl-hostname"
        })
        .unwrap();
        assert!(lists.is_empty(), "Empty lists should be skipped");
    }
}
