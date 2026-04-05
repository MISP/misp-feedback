use std::collections::HashSet;

use crate::matchers::cidr::CidrMatcher;
use crate::matchers::hostname::HostnameMatcher;
use crate::matchers::regex_matcher::RegexMatcher;
use crate::matchers::string::StringMatcher;
use crate::matchers::substring::SubstringMatcher;
use crate::model::{Category, ListType, RawWarningList, WarningListInfo};

pub struct MatchEngine {
    lists: Vec<WarningListInfo>,
    cidr_matcher: CidrMatcher,
    string_matcher: StringMatcher,
    hostname_matcher: HostnameMatcher,
    substring_matcher: SubstringMatcher,
    regex_matcher: RegexMatcher,
}

impl MatchEngine {
    /// Build the engine from loaded warninglists.
    /// `raw_lists` is a vec of (slug, RawWarningList) pairs.
    pub fn build(raw_lists: Vec<(String, RawWarningList)>) -> Self {
        let mut lists = Vec::with_capacity(raw_lists.len());
        let mut cidr_matcher = CidrMatcher::new();
        let mut string_matcher = StringMatcher::new();
        let mut hostname_matcher = HostnameMatcher::new();
        let mut substring_entries = Vec::new();
        let mut regex_entries = Vec::new();

        for (idx, (slug, raw)) in raw_lists.into_iter().enumerate() {
            lists.push(WarningListInfo {
                name: raw.name,
                description: raw.description,
                version: raw.version,
                list_type: raw.list_type,
                category: raw.category,
                entry_count: raw.list.len(),
                matching_attributes: raw.matching_attributes,
                slug,
            });

            match raw.list_type {
                ListType::Cidr => cidr_matcher.add_entries(&raw.list, idx),
                ListType::String => string_matcher.add_entries(&raw.list, idx),
                ListType::Hostname => hostname_matcher.add_entries(&raw.list, idx),
                ListType::Substring => {
                    for entry in &raw.list {
                        substring_entries.push((entry.clone(), idx));
                    }
                }
                ListType::Regex => {
                    for entry in &raw.list {
                        regex_entries.push((entry.clone(), idx));
                    }
                }
            }
        }

        let substring_matcher = SubstringMatcher::build(substring_entries);
        let regex_matcher = RegexMatcher::build(regex_entries);

        Self {
            lists,
            cidr_matcher,
            string_matcher,
            hostname_matcher,
            substring_matcher,
            regex_matcher,
        }
    }

    /// Look up a value against all matchers. Returns matching WarningListInfo references.
    pub fn lookup(&self, value: &str) -> Vec<&WarningListInfo> {
        if value.is_empty() {
            return Vec::new();
        }

        let mut seen = HashSet::new();
        let mut result = Vec::new();

        let all_indices = [
            self.cidr_matcher.lookup(value),
            self.string_matcher.lookup(value),
            self.hostname_matcher.lookup(value),
            self.substring_matcher.lookup(value),
            self.regex_matcher.lookup(value),
        ];

        for indices in &all_indices {
            for &idx in indices {
                if seen.insert(idx) {
                    result.push(&self.lists[idx]);
                }
            }
        }

        result
    }

    /// Look up a value, returning only matches from lists with the given category.
    pub fn lookup_by_category(&self, value: &str, category: Category) -> Vec<&WarningListInfo> {
        self.lookup(value)
            .into_iter()
            .filter(|info| info.category == category)
            .collect()
    }

    /// Get info about all loaded warninglists.
    pub fn lists(&self) -> &[WarningListInfo] {
        &self.lists
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::load_warninglists;
    use std::path::PathBuf;

    fn build_engine() -> MatchEngine {
        let lists_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("misp-warninglists/lists");
        let raw = load_warninglists(&lists_dir, &|_| true).unwrap();
        MatchEngine::build(raw)
    }

    #[test]
    fn cidr_lookup_8888() {
        let engine = build_engine();
        let matches = engine.lookup("8.8.8.8");
        let slugs: Vec<&str> = matches.iter().map(|m| m.slug.as_str()).collect();
        assert!(
            slugs.contains(&"public-dns-v4"),
            "Expected public-dns-v4 in {:?}",
            slugs
        );
    }

    #[test]
    fn hostname_google_com() {
        let engine = build_engine();
        let matches = engine.lookup("google.com");
        let slugs: Vec<&str> = matches.iter().map(|m| m.slug.as_str()).collect();
        // Should match in hostname lists (alexa, tranco) and string lists (cisco_top*)
        assert!(slugs.len() >= 5, "Expected 5+ matches for google.com, got {:?}", slugs);
    }

    #[test]
    fn hostname_subdomain_match() {
        let engine = build_engine();
        let matches = engine.lookup("mail.google.com");
        let slugs: Vec<&str> = matches.iter().map(|m| m.slug.as_str()).collect();
        assert!(
            !slugs.is_empty(),
            "Expected subdomain matches for mail.google.com"
        );
    }

    #[test]
    fn substring_match() {
        let engine = build_engine();
        let matches = engine.lookup("https://capesandbox.com/analysis/12345");
        let slugs: Vec<&str> = matches.iter().map(|m| m.slug.as_str()).collect();
        assert!(
            slugs.contains(&"automated-malware-analysis"),
            "Expected automated-malware-analysis in {:?}",
            slugs
        );
    }

    #[test]
    fn regex_match_email() {
        let engine = build_engine();
        let matches = engine.lookup("abuse@example.com");
        let slugs: Vec<&str> = matches.iter().map(|m| m.slug.as_str()).collect();
        assert!(
            slugs.contains(&"common-contact-emails"),
            "Expected common-contact-emails in {:?}",
            slugs
        );
    }

    #[test]
    fn no_match() {
        let engine = build_engine();
        let matches = engine.lookup("this-does-not-match-anything-12345.zzz");
        assert!(matches.is_empty());
    }

    #[test]
    fn empty_value() {
        let engine = build_engine();
        let matches = engine.lookup("");
        assert!(matches.is_empty());
    }

    #[test]
    fn perf_10k_mixed_lookups() {
        let engine = build_engine();

        // Build a corpus of 10,000 lookups with a mix of matcher types.
        // ~20% CIDR hits, ~20% hostname hits, ~20% string hits,
        // ~10% substring hits, ~10% regex hits, ~20% misses.
        let cidr_values = vec![
            "8.8.8.8",           // public-dns-v4
            "8.8.4.4",           // public-dns-v4
            "1.1.1.1",           // public-dns-v4
            "2606:4700::1111",   // public-dns-v6
            "103.11.223.1",      // akamai
            "1.178.1.50",        // amazon-aws
            "194.187.176.130",   // alphastrike-research-nt-scanning
            "45.83.64.1",        // alphastrike-scanning
            "13.32.0.1",         // amazon-aws
            "20.33.0.1",         // microsoft-azure
        ];

        let hostname_values = vec![
            "google.com",
            "facebook.com",
            "youtube.com",
            "mail.google.com",       // subdomain match
            "cdn.amazonaws.com",     // subdomain match
            "api.github.com",        // subdomain match
            "10086.cn",              // alexa
            "115.com",               // alexa
            "www.apple.com",         // subdomain match
            "login.microsoftonline.com", // subdomain match
        ];

        let string_values = vec![
            "1-courier.push.apple.com",  // cisco_top1000
            "android.clients.google.com", // captive-portals
            "captive.apple.com",         // captive-portals
            "apple.com",                 // captive-portals + hostname lists
            "1.nflxso.net",              // cisco_top1000
            "icanhazip.com",             // cisco_top1000 or similar
            "cloudflare.com",            // multiple lists
            "microsoft.com",             // multiple lists
            "amazon.com",                // multiple lists
            "github.com",               // multiple lists
        ];

        let substring_values = vec![
            "https://capesandbox.com/analysis/12345",
            "http://analyze.intezer.com/files/test",
            "https://anlyz.io/sample/abc",
            "http://akana.mobiseclab.org/report",
            "https://portal.docdeliveryapp.com/test",
            "http://portal.docdeliveryapp.net/phish",
            "https://app.any.run/tasks/12345",
            "http://bazaar.abuse.ch/sample/abc",
            "https://capesandbox.com/submit",
            "http://anlyz.io/details/xyz",
        ];

        let regex_values = vec![
            "abuse@example.com",
            "security@company.org",
            "noc@bigcorp.net",
            "soc@defense.io",
            "abuse@university.edu",
            "security@bank.com",
            "noc@isp.net",
            "soc@gov.mil",
            "abuse@hosting.co",
            "security@startup.io",
        ];

        let miss_values = vec![
            "this-does-not-match-anything-12345.zzz",
            "192.0.2.1",                     // TEST-NET, unlikely in warninglists
            "definitely-not-a-real-domain.invalid",
            "random-gibberish-abc123",
            "user@nonexistent-domain-xyz.test",
            "198.51.100.200",                // TEST-NET-2
            "unknown-service.example.test",
            "zzzz-no-match.local",
            "fake-indicator-00000",
            "203.0.113.50",                  // TEST-NET-3
        ];

        // Interleave to simulate realistic mixed workload
        let mut corpus: Vec<&str> = Vec::with_capacity(10_000);
        for i in 0..10_000 {
            let val = match i % 5 {
                0 => cidr_values[i / 5 % cidr_values.len()],
                1 => hostname_values[i / 5 % hostname_values.len()],
                2 => {
                    // Alternate string and substring for the "string-like" slot
                    if (i / 5) % 2 == 0 {
                        string_values[i / 5 % string_values.len()]
                    } else {
                        substring_values[i / 5 % substring_values.len()]
                    }
                }
                3 => regex_values[i / 5 % regex_values.len()],
                _ => miss_values[i / 5 % miss_values.len()],
            };
            corpus.push(val);
        }

        // Warm up
        for val in corpus.iter().take(100) {
            let _ = engine.lookup(val);
        }

        // Timed run
        let start = std::time::Instant::now();
        let mut total_matches: usize = 0;
        let mut hit_count: usize = 0;
        for val in &corpus {
            let matches = engine.lookup(val);
            if !matches.is_empty() {
                hit_count += 1;
                total_matches += matches.len();
            }
        }
        let elapsed = start.elapsed();

        let per_lookup = elapsed / corpus.len() as u32;

        // Print performance stats
        eprintln!();
        eprintln!("  ── Performance: 10k mixed lookups ──");
        eprintln!("  Total time:       {:?}", elapsed);
        eprintln!("  Per lookup (avg): {:?}", per_lookup);
        eprintln!("  Lookups/sec:      {:.0}", corpus.len() as f64 / elapsed.as_secs_f64());
        eprintln!("  Hit rate:         {}/{} ({:.1}%)", hit_count, corpus.len(), hit_count as f64 / corpus.len() as f64 * 100.0);
        eprintln!("  Total matches:    {} (avg {:.1} per hit)", total_matches, total_matches as f64 / hit_count.max(1) as f64);
        eprintln!();

        // Sanity checks: we expect a good portion of hits
        assert!(
            hit_count >= 6000,
            "Expected at least 60% hit rate, got {hit_count}/10000"
        );

        // Performance gate: 10k lookups should complete well under 5 seconds
        assert!(
            elapsed.as_secs() < 5,
            "10k lookups took {:?}, expected < 5s",
            elapsed
        );
    }
}
