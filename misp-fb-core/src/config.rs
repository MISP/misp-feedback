use serde::Deserialize;
use std::path::PathBuf;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub warninglists: WarninglistsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    pub http_bind: Option<String>,
    #[serde(default = "default_warninglists_path")]
    pub warninglists_path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WarninglistsConfig {
    #[serde(default)]
    pub lists: Vec<String>,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/tmp/misp-fbd.sock")
}

fn default_warninglists_path() -> PathBuf {
    PathBuf::from("./misp-warninglists/lists")
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        // Resolve relative paths against the config file's directory
        let config_dir = path
            .canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();

        if config.daemon.warninglists_path.is_relative() {
            config.daemon.warninglists_path =
                config_dir.join(&config.daemon.warninglists_path);
        }

        Ok(config)
    }
}

impl WarninglistsConfig {
    /// Build a filter function from the lists config.
    /// - Empty list: accept all
    /// - All entries with `!` prefix: accept all except those
    /// - All entries without `!` prefix: accept only those
    /// - Mixed: error
    pub fn build_filter(&self) -> Result<Box<dyn Fn(&str) -> bool + Send + Sync>> {
        if self.lists.is_empty() {
            return Ok(Box::new(|_| true));
        }

        let has_include = self.lists.iter().any(|s| !s.starts_with('!'));
        let has_exclude = self.lists.iter().any(|s| s.starts_with('!'));

        if has_include && has_exclude {
            return Err(Error::MixedIncludeExclude);
        }

        if has_exclude {
            let excluded: std::collections::HashSet<String> = self
                .lists
                .iter()
                .map(|s| s.strip_prefix('!').unwrap().to_string())
                .collect();
            Ok(Box::new(move |slug| !excluded.contains(slug)))
        } else {
            let included: std::collections::HashSet<String> =
                self.lists.iter().cloned().collect();
            Ok(Box::new(move |slug| included.contains(slug)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml = r#"
[daemon]
socket_path = "/tmp/test.sock"
http_bind = "127.0.0.1:3000"
warninglists_path = "/data/lists"

[warninglists]
lists = ["amazon-aws", "google-gcp"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.daemon.socket_path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.daemon.http_bind.as_deref(), Some("127.0.0.1:3000"));
        assert_eq!(config.daemon.warninglists_path, PathBuf::from("/data/lists"));
        assert_eq!(config.warninglists.lists, vec!["amazon-aws", "google-gcp"]);
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[daemon]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.daemon.socket_path, PathBuf::from("/tmp/misp-fbd.sock"));
        assert!(config.daemon.http_bind.is_none());
        assert_eq!(
            config.daemon.warninglists_path,
            PathBuf::from("./misp-warninglists/lists")
        );
        assert!(config.warninglists.lists.is_empty());
    }

    #[test]
    fn filter_empty_accepts_all() {
        let wc = WarninglistsConfig { lists: vec![] };
        let filter = wc.build_filter().unwrap();
        assert!(filter("anything"));
        assert!(filter("amazon-aws"));
    }

    #[test]
    fn filter_include_mode() {
        let wc = WarninglistsConfig {
            lists: vec!["amazon-aws".into(), "cloudflare".into()],
        };
        let filter = wc.build_filter().unwrap();
        assert!(filter("amazon-aws"));
        assert!(filter("cloudflare"));
        assert!(!filter("alexa"));
    }

    #[test]
    fn filter_exclude_mode() {
        let wc = WarninglistsConfig {
            lists: vec!["!alexa".into(), "!tranco".into()],
        };
        let filter = wc.build_filter().unwrap();
        assert!(!filter("alexa"));
        assert!(!filter("tranco"));
        assert!(filter("amazon-aws"));
    }

    #[test]
    fn filter_mixed_is_error() {
        let wc = WarninglistsConfig {
            lists: vec!["amazon-aws".into(), "!alexa".into()],
        };
        assert!(wc.build_filter().is_err());
    }
}
