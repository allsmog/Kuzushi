use super::prelude::*;
use super::*;

pub const MAX_REFERENCES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesInput {
    pub symbol: String,
    /// Optional file/directory to scope to (relative to root). Defaults to root.
    #[serde(default)]
    pub scope: Option<String>,
    /// Optional rg `--type` filter (e.g. `c`, `rust`, `java`).
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceHit {
    pub file: String,
    pub line: u32,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReferencesOutput {
    pub symbol: String,
    pub hits: Vec<ReferenceHit>,
    /// Number of hits the search produced before truncation.
    pub total_hits: usize,
    pub truncated: bool,
}

pub(in crate::code_nav) fn ripgrep_binary() -> String {
    std::env::var("KUZUSHI_RIPGREP_BIN").unwrap_or_else(|_| "rg".to_string())
}
