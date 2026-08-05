use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::canonical_json::canonical_json_bytes_without_key;
use super::census_report::CensusReport;
use super::feature_schema::{categorical_vocabulary, FEATURE_FIELD_NAMES};
use super::label_policy::{
    label_policy_manifest, DATASET_MANIFEST_SCHEMA_VERSION, FEATURE_SCHEMA_ID, LABEL_POLICY_ID,
    TASK_ID,
};

/// The exact projection and event-log state the dataset was read from, so a
/// later export can be told apart from this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetSourceRef {
    pub event_log_head_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log_head_hash: Option<String>,
    pub projection_applied_seq: u64,
    pub projection_generation: u64,
}

/// Sidecar manifest for a review-yield JSONL dataset.
///
/// Carries no wall-clock timestamp on purpose: two exports of an unchanged
/// projection must produce byte-identical files and the same digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetManifestV1 {
    pub schema_version: u32,
    pub task_id: String,
    /// Kuzushi version that produced the file. The core crate has no build
    /// commit constant, so the released version stands in for it.
    pub exporter_version: String,
    pub feature_schema_id: String,
    pub label_policy_id: String,
    pub label_policy: serde_json::Value,
    pub feature_fields: Vec<String>,
    /// `ruleFamily` also admits CWE-derived tokens outside the frozen
    /// vocabulary; this is the only shape they take.
    pub rule_family_pattern: String,
    pub categorical_vocabulary: BTreeMap<String, Vec<String>>,
    pub source: DatasetSourceRef,
    pub census: CensusReport,
    pub row_count: u64,
    /// `blake3:<hex>` over the manifest (this field removed) followed by every
    /// row, in exported order.
    pub dataset_digest: String,
}

impl DatasetManifestV1 {
    pub fn new(census: CensusReport, source: DatasetSourceRef, row_count: u64) -> Self {
        Self {
            schema_version: DATASET_MANIFEST_SCHEMA_VERSION,
            task_id: TASK_ID.to_string(),
            exporter_version: env!("CARGO_PKG_VERSION").to_string(),
            feature_schema_id: FEATURE_SCHEMA_ID.to_string(),
            label_policy_id: LABEL_POLICY_ID.to_string(),
            label_policy: label_policy_manifest(),
            feature_fields: FEATURE_FIELD_NAMES
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            rule_family_pattern: "^(cwe-[0-9]+|[a-z_]+)$".to_string(),
            categorical_vocabulary: categorical_vocabulary(),
            source,
            census,
            row_count,
            dataset_digest: String::new(),
        }
    }

    /// Canonical bytes the digest is computed over: the manifest as canonical
    /// JSON with `datasetDigest` removed.
    pub fn canonical_bytes_without_digest(&self) -> Result<Vec<u8>> {
        canonical_json_bytes_without_key(self, "datasetDigest")
    }
}
