use crate::findings::{Finding, ReviewDecisionRecord};
use crate::workspace::WorkspaceFindingExportRecord;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;

pub(super) fn attach_export_metadata(
    document: &mut Value,
    findings: &[Finding],
    decisions: &[ReviewDecisionRecord],
    metadata: &[WorkspaceFindingExportRecord],
    study: bool,
) -> Result<()> {
    document["runs"][0]["properties"]["kuzushiExport"] = json!({
        "scope": if study { "investigation" } else { "workspace_history" },
        "selection": "latest_recorded_confirmation",
        "sourceSemantics": "Recorded review decisions and observations; not a fresh scan or proof of current applicability. Missing observations do not establish a fix.",
    });
    let by_fingerprint = metadata
        .iter()
        .map(|record| (record.fingerprint.as_str(), record))
        .collect::<HashMap<_, _>>();
    let results = document["runs"][0]["results"]
        .as_array_mut()
        .context("Confirmed SARIF has no results array")?;
    for (result, finding) in results.iter_mut().zip(findings) {
        let record = by_fingerprint.get(finding.fingerprint.as_str()).copied();
        attach_finding_metadata(result, finding, decisions, record)?;
    }
    Ok(())
}

fn attach_finding_metadata(
    result: &mut Value,
    finding: &Finding,
    decisions: &[ReviewDecisionRecord],
    record: Option<&WorkspaceFindingExportRecord>,
) -> Result<()> {
    let latest = finding.id.and_then(|id| {
        decisions
            .iter()
            .filter(|record| record.finding_id == id)
            .max_by_key(|record| record.id)
    });
    let properties = result["properties"]
        .as_object_mut()
        .context("Confirmed SARIF result has no properties")?;
    properties.extend(json!({
        "kuzushiIdentityId": finding.identity_id,
        "kuzushiReviewDecision": record.map(|record| record.review_decision.as_str()).or_else(|| latest.map(|record| record.decision.verdict.as_str())),
        "kuzushiReviewDecisionAuthor": record.and_then(|record| record.review_decision_author.as_deref()).or_else(|| latest.map(|record| record.decision.author.as_str())),
        "kuzushiReviewDecisionReason": record.and_then(|record| record.review_decision_reason.as_deref()).or_else(|| latest.map(|record| record.decision.rationale.as_str())),
        "kuzushiReviewDecisionBasis": null_or_record_basis(record),
        "kuzushiSuppressed": finding.suppressed,
        "kuzushiConfidence": record.and_then(|record| record.confidence),
        "kuzushiReviewDecisionConflict": record.and_then(|record| record.review_decision_conflict.as_deref()),
        "kuzushiProvenance": record.map(|record| &record.provenance),
        "kuzushiRelationships": record.map(|record| &record.relationships),
        "kuzushiLessons": record.map(|record| &record.lessons),
        "kuzushiSourceApplicability": record.and_then(|record| record.review_decision_basis.as_ref()).map(|basis| basis.source_applicability),
        "kuzushiSourceApplicabilityBasis": "recorded_observations",
        "kuzushiCurrentCheckoutApplicability": "not_assessed",
        "kuzushiRunId": finding.scan_id,
    }).as_object().context("Could not project confirmed SARIF metadata")?.clone());
    Ok(())
}

fn null_or_record_basis(record: Option<&WorkspaceFindingExportRecord>) -> Value {
    record
        .and_then(|record| record.review_decision_basis.as_ref())
        .map_or(Value::Null, |basis| json!(basis))
}

#[cfg(test)]
mod tests;
