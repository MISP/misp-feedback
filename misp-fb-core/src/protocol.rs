//! Shared request/response types for the misp-fbd HTTP API.
//!
//! Both the daemon (server) and CLI (client) use these types so that
//! serialisation stays in sync.

use serde::{Deserialize, Serialize};

use crate::model::{Category, ListType, WarningListInfo};

// ── Requests ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupRequest {
    pub value: String,
    /// If true, only return matches from false-positive warninglists.
    #[serde(default)]
    pub false_positives_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupRequest {
    pub values: Vec<String>,
    /// If true, only return matches from false-positive warninglists.
    #[serde(default)]
    pub false_positives_only: bool,
}

// ── Responses ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub lists_loaded: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LookupResponse {
    pub value: String,
    pub matched: bool,
    pub matches: Vec<MatchInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInfo {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub list_type: ListType,
    pub category: Category,
    pub matching_attributes: Vec<String>,
}

impl From<&WarningListInfo> for MatchInfo {
    fn from(info: &WarningListInfo) -> Self {
        Self {
            slug: info.slug.clone(),
            name: info.name.clone(),
            description: info.description.clone(),
            list_type: info.list_type,
            category: info.category,
            matching_attributes: info.matching_attributes.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupResponse {
    pub results: Vec<LookupResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListsResponse {
    pub count: usize,
    pub lists: Vec<WarningListInfo>,
}
