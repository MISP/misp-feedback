use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ListType {
    Cidr,
    String,
    Hostname,
    Substring,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    FalsePositive,
    Known,
}

impl Default for Category {
    fn default() -> Self {
        Self::FalsePositive
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawWarningList {
    pub name: std::string::String,
    pub description: std::string::String,
    pub version: u64,
    #[serde(rename = "type")]
    pub list_type: ListType,
    pub list: Vec<std::string::String>,
    #[serde(default)]
    pub matching_attributes: Vec<std::string::String>,
    #[serde(default)]
    pub category: Category,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarningListInfo {
    pub name: std::string::String,
    pub description: std::string::String,
    pub version: u64,
    pub list_type: ListType,
    pub category: Category,
    pub entry_count: usize,
    pub matching_attributes: Vec<std::string::String>,
    pub slug: std::string::String,
}
