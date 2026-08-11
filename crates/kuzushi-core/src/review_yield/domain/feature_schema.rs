use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::canonical_json::canonical_json_bytes;
use super::label_policy::FEATURE_SCHEMA_ID;
use super::normalizers::{
    rule_family_keyword_tokens, EVIDENCE_KINDS, GROUNDING_STATUSES, IDENTITY_MATCH_TIERS,
    STATIC_PROOF_STATES, TOOL_FAMILIES, VULN_SOURCES,
};
use super::path_bucket::PATH_BUCKETS;

/// The complete, frozen feature whitelist for `kuzushi-review-yield-features-v1`.
///
/// Every field here is derivable from a finding snapshot that predates the
/// reviewer's read cutoff. Nothing on this struct can carry a raw path, a code
/// snippet, a message, a rationale, a reviewer identity, or any triage or
/// verification outcome — those keys are not deserialized at all (see
/// `application::extract_features::AnchorSnapshotView`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewYieldFeaturesV1 {
    /// 0 = critical … 5 = unknown.
    pub severity_rank: u8,
    pub static_proof_state: String,
    pub vuln_source: String,
    pub tool_family: String,
    pub rule_family: String,
    pub path_bucket: String,
    pub language_family: String,
    pub identity_match_tier: String,
    pub grounding_status: String,
    pub is_attack_chain: bool,
    pub evidence_count: u32,
    pub distinct_evidence_kinds: u32,
    /// `None` when the finding carries no evidence — absence is reported, not
    /// imputed as zero.
    pub max_evidence_confidence: Option<u8>,
    /// Mean evidence confidence in thousandths (0..=1000), `None` when there
    /// is no evidence.
    pub mean_evidence_confidence_millis: Option<u32>,
    pub has_source_evidence: bool,
    pub has_sink_evidence: bool,
    pub has_sanitizer_evidence: bool,
    pub has_call_path_evidence: bool,
    pub source_sink_linked: bool,
    pub sanitizer_checked: bool,
    pub has_exploit_scenario: bool,
    pub precondition_count: u32,
    pub source_count: u32,
    pub distinct_tool_count: u32,
    pub corroboration_count: u32,
    pub observation_count: u32,
    pub run_count: u32,
    pub reopened_count: u32,
    /// Experimental: producers populate `$.remediation` inconsistently.
    pub has_remediation: bool,
}

/// The frozen field order of `ReviewYieldFeaturesV1` as serialized.
pub const FEATURE_FIELD_NAMES: &[&str] = &[
    "severityRank",
    "staticProofState",
    "vulnSource",
    "toolFamily",
    "ruleFamily",
    "pathBucket",
    "languageFamily",
    "identityMatchTier",
    "groundingStatus",
    "isAttackChain",
    "evidenceCount",
    "distinctEvidenceKinds",
    "maxEvidenceConfidence",
    "meanEvidenceConfidenceMillis",
    "hasSourceEvidence",
    "hasSinkEvidence",
    "hasSanitizerEvidence",
    "hasCallPathEvidence",
    "sourceSinkLinked",
    "sanitizerChecked",
    "hasExploitScenario",
    "preconditionCount",
    "sourceCount",
    "distinctToolCount",
    "corroborationCount",
    "observationCount",
    "runCount",
    "reopenedCount",
    "hasRemediation",
];

/// Domain separator for the feature-snapshot digest. Distinct from the model
/// digest domain so a feature vector and a model artifact can never produce the
/// same hash from the same bytes.
pub const FEATURE_SNAPSHOT_DOMAIN: &str = "kuzushi-review-yield-feature-snapshot-v1";

/// `blake3:<hex>` over the canonical feature vector.
///
/// This is what a recorded review session carries instead of the features
/// themselves: an evaluator can regenerate the vector from the same cutoff and
/// check the digest, while the event log never stores a feature value.
pub fn feature_snapshot_hash(features: &ReviewYieldFeaturesV1) -> Result<String> {
    let canonical = canonical_json_bytes(features)?;
    let digest = crate::identity::hash_parts(
        FEATURE_SNAPSHOT_DOMAIN,
        &[FEATURE_SCHEMA_ID.as_bytes(), &canonical],
    );
    Ok(format!("blake3:{digest}"))
}

/// The closed vocabulary of every categorical feature, recorded in the dataset
/// manifest so a consumer can encode the categories without re-deriving them.
pub fn categorical_vocabulary() -> BTreeMap<String, Vec<String>> {
    let mut vocabulary = BTreeMap::new();
    for (feature, tokens) in categorical_token_sources() {
        vocabulary.insert(feature.to_string(), sorted_tokens(&tokens));
    }
    vocabulary
}

fn categorical_token_sources() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("staticProofState", STATIC_PROOF_STATES.to_vec()),
        ("vulnSource", VULN_SOURCES.to_vec()),
        ("toolFamily", TOOL_FAMILIES.to_vec()),
        ("ruleFamily", rule_family_keyword_tokens()),
        ("pathBucket", PATH_BUCKETS.to_vec()),
        ("identityMatchTier", IDENTITY_MATCH_TIERS.to_vec()),
        ("groundingStatus", GROUNDING_STATUSES.to_vec()),
        ("evidenceKind", EVIDENCE_KINDS.to_vec()),
    ]
}

fn sorted_tokens(tokens: &[&'static str]) -> Vec<String> {
    let mut values: Vec<String> = tokens.iter().map(|token| (*token).to_string()).collect();
    values.sort();
    values.dedup();
    values
}
