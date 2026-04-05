use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error in {path}: {source}")]
    JsonParse {
        path: String,
        source: serde_json::Error,
    },

    #[error("Config error: {0}")]
    Config(String),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("Invalid CIDR: {0}")]
    InvalidCidr(String),

    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),

    #[error("Mixed include/exclude in warninglists.lists config")]
    MixedIncludeExclude,
}

pub type Result<T> = std::result::Result<T, Error>;
