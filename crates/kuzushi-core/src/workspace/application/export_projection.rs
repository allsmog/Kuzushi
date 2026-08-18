use crate::findings::{
    derive_triage_state, finding_lifecycle_status, proof_state_label, runtime_validation_label,
    Finding, FindingTriageState, PersistedVerification, ProofConfidence, StableLifecycleStatus,
    StaticProofState, TriageAuthor, VulnSource,
};
use std::collections::HashMap;

use super::export_evidence_origin::{
    evidence_origin_counts, evidence_state_label, EvidenceOriginCounts,
};
use super::export_projection_model::{
    WorkspaceAnalysisExportSummary, WorkspaceDismissalExportSummary,
    WorkspaceEvidenceExportSummary, WorkspaceFindingExportLocation, WorkspaceFindingExportRecord,
    WorkspaceFindingProvenanceSummary, WorkspaceRunExportContext,
    WorkspaceVerificationExportSummary,
};
use super::export_review_context::WorkspaceFindingReviewContext;

struct WorkspaceReviewExportSummary {
    confidence: Option<f32>,
    review_decision: String,
    triage_state: String,
    dismissal: Option<WorkspaceDismissalExportSummary>,
    review_decision_conflict: Option<String>,
    review_decision_reason: Option<String>,
    review_decision_author: Option<String>,
    triage_verdict: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkspaceFindingExportPosition {
    pub alias: String,
    pub priority_index: usize,
}

pub fn workspace_finding_export_records_with_reviews(
    findings: &[Finding],
    reviews: &[Option<WorkspaceFindingReviewContext>],
) -> Vec<WorkspaceFindingExportRecord> {
    workspace_finding_export_records_with_context(findings, reviews, &HashMap::new())
}

pub fn workspace_finding_export_records_with_context(
    findings: &[Finding],
    reviews: &[Option<WorkspaceFindingReviewContext>],
    run_contexts: &HashMap<String, WorkspaceRunExportContext>,
) -> Vec<WorkspaceFindingExportRecord> {
    let positions = workspace_finding_export_positions(findings);
    workspace_finding_export_records_at_positions(findings, reviews, run_contexts, &positions)
}

pub(super) fn workspace_finding_export_positions(
    findings: &[Finding],
) -> Vec<WorkspaceFindingExportPosition> {
    let mut positions = vec![None; findings.len()];
    for (priority_index, (alias, finding_index)) in
        crate::findings::sorted_finding_alias_indices(findings)
            .into_iter()
            .enumerate()
    {
        positions[finding_index] = Some(WorkspaceFindingExportPosition {
            alias,
            priority_index,
        });
    }
    positions
        .into_iter()
        .map(|position| position.expect("alias projection covers every finding"))
        .collect()
}

pub(super) fn workspace_finding_export_records_at_positions(
    findings: &[Finding],
    reviews: &[Option<WorkspaceFindingReviewContext>],
    run_contexts: &HashMap<String, WorkspaceRunExportContext>,
    positions: &[WorkspaceFindingExportPosition],
) -> Vec<WorkspaceFindingExportRecord> {
    let mut records = findings
        .iter()
        .zip(positions)
        .enumerate()
        .map(|(finding_index, (finding, position))| {
            let review = reviews.get(finding_index).and_then(Option::as_ref);
            let run_context = finding
                .scan_id
                .as_ref()
                .and_then(|run_id| run_contexts.get(run_id));
            (
                position.priority_index,
                export_record(
                    position.priority_index,
                    position.alias.clone(),
                    finding.clone(),
                    review,
                    run_context,
                ),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|(priority_index, _)| *priority_index);
    records.into_iter().map(|(_, record)| record).collect()
}

fn export_record(
    index: usize,
    alias: String,
    finding: Finding,
    review_context: Option<&WorkspaceFindingReviewContext>,
    run_context: Option<&WorkspaceRunExportContext>,
) -> WorkspaceFindingExportRecord {
    let review = review_summary(&finding, review_context);
    let vuln_source = vuln_source_label(&finding);
    let provenance = provenance_summary(&finding, &vuln_source, run_context);
    let analysis = analysis_summary(&finding, &review);
    let mut record = base_export_record(index, alias, finding, vuln_source, provenance);
    apply_review_summary(&mut record, review, analysis);
    record
}

fn base_export_record(
    index: usize,
    alias: String,
    finding: Finding,
    vuln_source: String,
    provenance: WorkspaceFindingProvenanceSummary,
) -> WorkspaceFindingExportRecord {
    let mut record = WorkspaceFindingExportRecord {
        alias,
        identity_id: finding.identity_id.clone(),
        fingerprint: finding.fingerprint.clone(),
        kind: "scanner_finding".to_string(),
        rule_id: finding.rule_id.clone(),
        title: finding.title.clone(),
        cwe: crate::findings::extract_cwe(&finding.rule_id, &finding.title, &finding.message),
        location: finding_location(&finding),
        severity: finding.severity.as_str().to_string(),
        confidence: None,
        priority: format!("review-order:{}", index + 1),
        lifecycle_status: finding_lifecycle_status(&finding).to_string(),
        review_decision: "needs_review".to_string(),
        suppressed: finding.suppressed,
        snoozed_until: finding.snoozed_until.clone(),
        evidence: evidence_summary(&finding),
        static_proof_state: static_proof_state(&finding).to_string(),
        static_proof_label: proof_state_label(finding.static_proof_state).to_string(),
        proof_confidence: ProofConfidence::classify(&finding).as_str().to_string(),
        verification: verification_summary(finding.verification.as_ref()),
        tool: finding.tool.clone(),
        vuln_source,
        source_signature: finding.source_signature.clone(),
        corroboration_count: finding.corroboration_count,
        run_id: finding.scan_id.clone(),
        provenance,
        ..WorkspaceFindingExportRecord::default()
    };
    apply_hunt_enrichment(&mut record, &finding);
    record
}

/// The hunt-authored plain-language fields (recommendation from remediation,
/// impact, category, exploit scenario, preconditions) ride the finding blob
/// and pass through unmodified — honest-empty when the producer never
/// supplied them.
fn apply_hunt_enrichment(record: &mut WorkspaceFindingExportRecord, finding: &Finding) {
    record.recommendation = finding.remediation.clone();
    record.impact = finding.impact.clone();
    record.category = finding.category.clone();
    record.exploit_scenario = finding.exploit_scenario.clone();
    record.preconditions = finding.preconditions.clone();
    record.references = finding.references.clone();
    record.message = finding.message.clone();
}

fn apply_review_summary(
    record: &mut WorkspaceFindingExportRecord,
    review: WorkspaceReviewExportSummary,
    analysis: WorkspaceAnalysisExportSummary,
) {
    record.confidence = review.confidence;
    record.review_decision = review.review_decision;
    record.triage_state = review.triage_state;
    record.dismissal = review.dismissal;
    record.review_decision_conflict = review.review_decision_conflict;
    record.review_decision_reason = review.review_decision_reason;
    record.review_decision_author = review.review_decision_author;
    record.triage_verdict = review.triage_verdict;
    record.analysis = analysis;
}

fn review_summary(
    finding: &Finding,
    review_context: Option<&WorkspaceFindingReviewContext>,
) -> WorkspaceReviewExportSummary {
    let fallback_review;
    let review = match review_context {
        Some(review) => Some(review),
        None => {
            fallback_review = WorkspaceFindingReviewContext::from_finding(finding);
            fallback_review.as_ref()
        }
    };
    let derived = review
        .map(|review| derive_triage_state(StableLifecycleStatus::Open, Some(&review.decision)))
        .unwrap_or(FindingTriageState::Open);
    WorkspaceReviewExportSummary {
        confidence: review.map(|review| review.decision.confidence),
        review_decision: review
            .map(|review| review.decision.verdict.as_str().to_string())
            .unwrap_or_else(|| "needs_review".to_string()),
        triage_state: derived.as_str().to_string(),
        dismissal: review
            .and_then(|review| dismissal_summary(&review.decision, review.decided_at.clone())),
        review_decision_conflict: review
            .and_then(|review| review.decision_conflict_label(finding).map(str::to_string)),
        review_decision_reason: review.and_then(|review| non_empty_str(&review.decision.rationale)),
        review_decision_author: review.map(|review| review.decision.author.as_str().to_string()),
        triage_verdict: review
            .and_then(|review| review.triage_verdict)
            .map(|verdict| verdict.as_str().to_string()),
    }
}

fn dismissal_summary(
    decision: &crate::findings::ReviewDecision,
    decided_at: Option<String>,
) -> Option<WorkspaceDismissalExportSummary> {
    // Only a human dismissal is a real suppression. An LLM auto-triage
    // (author == Auto) must never emit a SARIF suppression asserting a human
    // accepted the risk — mirror `human_decision_state` in the domain fold.
    if decision.author != TriageAuthor::Human {
        return None;
    }
    let reason = decision.effective_dismiss_reason()?;
    Some(WorkspaceDismissalExportSummary {
        reason: reason.as_str().to_string(),
        note: decision.rationale.clone(),
        actor: decision.actor.clone(),
        at: decided_at,
    })
}

fn vuln_source_label(finding: &Finding) -> String {
    finding
        .vuln_source
        .unwrap_or_else(|| VulnSource::from_tool(&finding.tool))
        .as_str()
        .to_string()
}

fn finding_location(finding: &Finding) -> WorkspaceFindingExportLocation {
    WorkspaceFindingExportLocation {
        file: finding.file_path.clone(),
        start_line: finding.start_line,
        end_line: finding.end_line,
    }
}

fn non_empty_str(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn evidence_summary(finding: &Finding) -> WorkspaceEvidenceExportSummary {
    let counts = evidence_origin_counts(&finding.evidence);
    WorkspaceEvidenceExportSummary {
        state: evidence_state(finding, &counts).to_string(),
        observed_evidence_present: counts.observed_count > 0,
        observed_count: counts.observed_count,
        observed_code_count: counts.observed_code_count,
        observed_capture_count: counts.observed_capture_count,
        observed_other_count: counts.observed_other_count,
        model_generated_reasoning_present: counts.model_generated_reasoning_count > 0,
        model_generated_reasoning_count: counts.model_generated_reasoning_count,
        derived_source_present: derived_source_present(finding),
        source_count: finding.sources.len(),
        raw_http_blob_present: counts.observed_capture_count > 0,
        evidence_confidence_max: evidence_confidence_max(finding),
    }
}

fn evidence_confidence_max(finding: &Finding) -> Option<u8> {
    finding
        .evidence
        .iter()
        .map(|evidence| evidence.confidence)
        .filter(|confidence| *confidence > 0)
        .max()
}

fn derived_source_present(finding: &Finding) -> bool {
    matches!(
        finding.static_proof_state,
        Some(
            StaticProofState::CodeCited
                | StaticProofState::SourceSinkLinked
                | StaticProofState::SanitizerChecked
                | StaticProofState::StaticallyConfirmed
                | StaticProofState::StaticallyRejected
        )
    )
}

fn analysis_summary(
    finding: &Finding,
    review: &WorkspaceReviewExportSummary,
) -> WorkspaceAnalysisExportSummary {
    WorkspaceAnalysisExportSummary {
        static_proof_recorded: finding.static_proof_state.is_some(),
        automated_reasoning_present: automated_reasoning_present(finding, review),
        human_review_present: review.review_author_is("human"),
        imported_review_present: review.review_author_is("imported"),
    }
}

fn automated_reasoning_present(finding: &Finding, review: &WorkspaceReviewExportSummary) -> bool {
    review.review_author_is("auto") && review.review_decision_reason.is_some()
        || evidence_origin_counts(&finding.evidence).model_generated_reasoning_count > 0
}

impl WorkspaceReviewExportSummary {
    fn review_author_is(&self, author: &str) -> bool {
        self.review_decision_author.as_deref() == Some(author)
    }
}

fn evidence_state(finding: &Finding, counts: &EvidenceOriginCounts) -> &'static str {
    evidence_state_label(
        counts.observed_count > 0,
        counts.model_generated_reasoning_count > 0,
        finding.corroboration_count > 1 || finding.sources.len() > 1,
        derived_source_present(finding),
    )
}

fn static_proof_state(finding: &Finding) -> &'static str {
    finding
        .static_proof_state
        .map(StaticProofState::as_str)
        .unwrap_or("not_recorded")
}

fn verification_summary(
    verification: Option<&PersistedVerification>,
) -> WorkspaceVerificationExportSummary {
    WorkspaceVerificationExportSummary {
        label: runtime_validation_label(verification),
        verdict: verification.map(|verification| verification.proof_verdict.as_str().to_string()),
        proof_level: verification.map(|verification| verification.proof_level),
        backend: verification.map(|verification| verification.backend.as_str().to_string()),
        language: verification.and_then(|verification| verification.language.clone()),
        source_identity: verification.and_then(|verification| {
            verification
                .provenance
                .as_ref()
                .map(|provenance| provenance.source_identity.clone())
        }),
        reproducer: verification.and_then(|verification| {
            verification
                .provenance
                .as_ref()
                .and_then(|provenance| provenance.reproducer.clone())
        }),
    }
}

fn provenance_summary(
    finding: &Finding,
    vuln_source: &str,
    run_context: Option<&WorkspaceRunExportContext>,
) -> WorkspaceFindingProvenanceSummary {
    WorkspaceFindingProvenanceSummary {
        tool: finding.tool.clone(),
        vuln_source: vuln_source.to_string(),
        source_signature: finding.source_signature.clone(),
        corroboration_count: finding.corroboration_count,
        run_id: finding.scan_id.clone(),
        run_status: run_context.and_then(|context| context.status.clone()),
        kuzushi_version: run_context.and_then(|context| context.kuzushi_version.clone()),
        model: run_context.and_then(|context| context.model.clone()),
        runtime_platform: run_context.and_then(|context| context.runtime_platform.clone()),
    }
}

#[cfg(test)]
#[path = "tests/export_projection.rs"]
mod tests;
