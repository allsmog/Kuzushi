use super::prelude::*;
use super::*;

pub(crate) const WHITEBOX_SUPPRESSION_STORE_NAME: &str = "whitebox-suppressions.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionScope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_fingerprint: Option<String>,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionEvidence {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionRecord {
    pub id: String,
    pub scope: WhiteboxSuppressionScope,
    pub evidence: Vec<WhiteboxSuppressionEvidence>,
    pub reason: String,
    pub author: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionMatch {
    pub finding_fingerprint: String,
    pub suppression_id: String,
    pub reason: String,
    pub author: String,
    pub expires_at_unix: u64,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaleSuppression {
    pub suppression_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub expected_snippet_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_snippet_hash: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxExpiredSuppression {
    pub suppression_id: String,
    pub expired_at_unix: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxSuppressionReport {
    pub total_suppressions: usize,
    pub active_suppressions: usize,
    pub suppressed_count: usize,
    pub suppressed_findings: Vec<WhiteboxSuppressionMatch>,
    pub stale_suppressions: Vec<WhiteboxStaleSuppression>,
    pub expired_suppressions: Vec<WhiteboxExpiredSuppression>,
    pub findings_remain_visible: bool,
    pub audit_note: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WhiteboxSuppressionStoreFile {
    pub(crate) version: u8,
    pub(crate) suppressions: Vec<WhiteboxSuppressionRecord>,
}
