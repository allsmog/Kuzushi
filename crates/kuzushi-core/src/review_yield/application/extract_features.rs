use std::collections::BTreeSet;

use anyhow::{Context, Result};

use super::anchor_snapshot::{AnchorSnapshotView, EvidenceView};
use crate::findings::StaticProofState;
use crate::review_yield::domain::{
    grounding_token, identity_match_tier, is_attack_chain, language_family,
    normalize_evidence_kind, path_bucket, rule_family, severity_rank, static_proof_token,
    tool_family, vuln_source_token, ReviewYieldFeaturesV1,
};
use crate::review_yield::persistence::ObservationMeta;

/// Upper bound on the evidence a feature vector may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureCutoff {
    /// Only history at or before this event sequence.
    EventSeq(u64),
    /// No upper bound — the live projection head. Used by runtime scoring,
    /// which must go through this same extractor.
    ProjectionHead,
}

impl FeatureCutoff {
    fn admits(self, created_seq: u64) -> bool {
        match self {
            Self::EventSeq(cutoff) => created_seq <= cutoff,
            Self::ProjectionHead => true,
        }
    }
}

/// Everything the extractor is allowed to read for one identity.
pub struct ReviewFeatureSource {
    pub anchor_json: String,
    pub history: Vec<ObservationMeta>,
    pub reopened_count: u32,
}

/// Builds the v1 feature vector. The cutoff is enforced here as well as by the
/// caller, so training extraction and runtime scoring cannot diverge.
pub fn extract_review_yield_features(
    source: &ReviewFeatureSource,
    cutoff: FeatureCutoff,
) -> Result<ReviewYieldFeaturesV1> {
    let anchor: AnchorSnapshotView = serde_json::from_str(&source.anchor_json)
        .context("review-yield anchor snapshot is not a readable finding record")?;
    let history: Vec<&ObservationMeta> = source
        .history
        .iter()
        .filter(|observation| cutoff.admits(observation.created_seq))
        .collect();
    Ok(assemble(
        &anchor,
        &evidence_stats(&anchor.evidence),
        &history_stats(&history),
        source.reopened_count,
    ))
}

struct EvidenceStats {
    count: u32,
    kinds: BTreeSet<&'static str>,
    max_confidence: Option<u8>,
    mean_confidence_millis: Option<u32>,
}

impl EvidenceStats {
    fn has(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }
}

struct HistoryStats {
    observation_count: u32,
    run_count: u32,
    distinct_tool_count: u32,
}

fn evidence_stats(evidence: &[EvidenceView]) -> EvidenceStats {
    let confidences: Vec<u32> = evidence
        .iter()
        .map(|item| u32::from(item.confidence))
        .collect();
    EvidenceStats {
        count: evidence.len() as u32,
        kinds: evidence
            .iter()
            .map(|item| normalize_evidence_kind(&item.kind))
            .collect(),
        max_confidence: evidence.iter().map(|item| item.confidence).max(),
        mean_confidence_millis: mean_millis(&confidences),
    }
}

/// Mean confidence in thousandths. `None` for no evidence: absence is a
/// distinct state from a mean of zero.
fn mean_millis(confidences: &[u32]) -> Option<u32> {
    let count = u32::try_from(confidences.len()).ok().filter(|n| *n > 0)?;
    let total: u32 = confidences.iter().sum();
    Some(total.saturating_mul(10) / count)
}

fn history_stats(history: &[&ObservationMeta]) -> HistoryStats {
    HistoryStats {
        observation_count: history.len() as u32,
        run_count: distinct_count(history.iter().map(|item| item.run_id.as_str())),
        distinct_tool_count: distinct_count(history.iter().map(|item| tool_family(&item.tool))),
    }
}

fn distinct_count<'a>(values: impl Iterator<Item = &'a str>) -> u32 {
    values.collect::<BTreeSet<&str>>().len() as u32
}

fn assemble(
    anchor: &AnchorSnapshotView,
    evidence: &EvidenceStats,
    history: &HistoryStats,
    reopened_count: u32,
) -> ReviewYieldFeaturesV1 {
    ReviewYieldFeaturesV1 {
        severity_rank: severity_rank(anchor.severity),
        static_proof_state: static_proof_token(anchor.static_proof_state).to_string(),
        vuln_source: vuln_source_token(anchor.vuln_source).to_string(),
        tool_family: tool_family(&anchor.tool).to_string(),
        rule_family: rule_family(anchor.category.as_deref(), &anchor.rule_id),
        path_bucket: path_bucket(&anchor.file_path).to_string(),
        language_family: language_family(&anchor.file_path),
        identity_match_tier: identity_match_tier(anchor.identity_match_tier.as_deref()).to_string(),
        grounding_status: grounding_token(anchor.grounding.as_ref()).to_string(),
        is_attack_chain: is_attack_chain(&anchor.tool, &anchor.rule_id),
        evidence_count: evidence.count,
        distinct_evidence_kinds: evidence.kinds.len() as u32,
        max_evidence_confidence: evidence.max_confidence,
        mean_evidence_confidence_millis: evidence.mean_confidence_millis,
        has_source_evidence: evidence.has("source"),
        has_sink_evidence: evidence.has("sink"),
        has_sanitizer_evidence: evidence.has("sanitizer"),
        has_call_path_evidence: evidence.has("call_path"),
        source_sink_linked: source_sink_linked(anchor, evidence),
        sanitizer_checked: sanitizer_checked(anchor, evidence),
        has_exploit_scenario: is_populated(anchor.exploit_scenario.as_deref()),
        precondition_count: anchor.preconditions.len() as u32,
        source_count: anchor.sources.len() as u32,
        distinct_tool_count: history.distinct_tool_count,
        corroboration_count: anchor.corroboration_count,
        observation_count: history.observation_count,
        run_count: history.run_count,
        reopened_count,
        has_remediation: is_populated(anchor.remediation.as_deref()),
    }
}

fn source_sink_linked(anchor: &AnchorSnapshotView, evidence: &EvidenceStats) -> bool {
    matches!(
        anchor.static_proof_state,
        Some(StaticProofState::SourceSinkLinked)
            | Some(StaticProofState::SanitizerChecked)
            | Some(StaticProofState::StaticallyConfirmed)
    ) || (evidence.has("source") && evidence.has("sink"))
}

fn sanitizer_checked(anchor: &AnchorSnapshotView, evidence: &EvidenceStats) -> bool {
    anchor.static_proof_state == Some(StaticProofState::SanitizerChecked)
        || evidence.has("sanitizer")
}

fn is_populated(value: Option<&str>) -> bool {
    value.is_some_and(|text| !text.trim().is_empty())
}
