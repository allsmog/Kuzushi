//! Typed structured-output contracts for finding producers.
//!
//! These types exist so the JSON schema handed to the model is generated from
//! Rust (via `schemars`) with the canonical [`Severity`] and [`ConfidenceBand`]
//! enums as the single source of truth. Renaming an enum variant changes the
//! generated schema and trips the drift test in this module.
//!
//! The types are intentionally permissive (most fields optional, unknown keys
//! allowed) because the downstream normalizer reads fields flexibly and repairs
//! deviations; the schema's job here is to communicate the canonical shape and
//! enum vocabularies to the model, not to hard-reject output.

use crate::findings::{ConfidenceBand, Severity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One candidate finding as emitted by an LLM finding producer.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FindingCandidate {
    /// Short rule identifier, e.g. `sql-injection`.
    pub rule_id: String,
    /// Repository-relative path of the vulnerable code.
    pub file_path: String,
    pub start_line: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceBand>,
    /// Short finding summary.
    pub message: String,
    /// Source-to-sink proof or local evidence with file:line citations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe: Vec<String>,
}

/// The enforced top-level output of a finding producer.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FindingsOutput {
    pub findings: Vec<FindingCandidate>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_output::StructuredJsonContract;

    #[test]
    fn generated_schema_carries_canonical_enum_vocabularies() {
        let contract =
            StructuredJsonContract::from_schema::<FindingsOutput>("agentic-sast:scan", "Findings");
        let schema = serde_json::to_string(&contract.runtime_contract().schema).unwrap();
        // Canonical severity band — renaming a Severity variant breaks this.
        for severity in ["critical", "high", "medium", "low", "info", "unknown"] {
            assert!(
                schema.contains(&format!("\"{severity}\"")),
                "severity {severity} missing from generated schema"
            );
        }
        // Canonical confidence band — renaming a ConfidenceBand variant breaks this.
        for band in ["high", "medium", "low"] {
            assert!(schema.contains(&format!("\"{band}\"")));
        }
        // Structural: the top-level `findings` array is present.
        assert!(schema.contains("findings"));
    }
}
