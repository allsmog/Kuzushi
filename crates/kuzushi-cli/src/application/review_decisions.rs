use crate::application::findings::resolve_persisted_finding;
use crate::support::require_cli_target;
use anyhow::{Context, Result};
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::workspace::record_user_review_decision_for_finding;
use kuzushi_core::{Finding, FindingStore, WorkspaceTarget};
use serde_json::json;
use std::path::PathBuf;

pub(crate) fn decision_command(
    target: Option<PathBuf>,
    reference: String,
    verdict: String,
    reason: String,
    json_output: bool,
) -> Result<()> {
    let target = require_cli_target("decision", target, None)?;
    let verdict = review_decision_verdict_from_input(&verdict)?;
    let reason = non_empty_decision_reason(reason)?;
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = resolve_persisted_finding(&store, &reference, &workspace)?;
    let decision = human_review_decision(verdict, reason);
    let decision_id = record_user_review_decision_for_finding(&workspace, &finding, &decision)?;
    print_decision_command_result(&finding, decision_id, &decision, json_output)
}

fn review_decision_verdict_from_input(value: &str) -> Result<ReviewDecisionVerdict> {
    let normalized = value.trim().replace('-', "_");
    ReviewDecisionVerdict::from_str(&normalized).with_context(|| {
        format!(
            "unsupported review decision {value:?}. Expected confirmed, rejected_false_positive, suppressed, deferred, accepted_risk, or needs_review"
        )
    })
}

fn non_empty_decision_reason(reason: String) -> Result<String> {
    let reason = reason.trim().to_string();
    if reason.is_empty() {
        anyhow::bail!("review decision reason cannot be empty");
    }
    Ok(reason)
}

fn human_review_decision(verdict: ReviewDecisionVerdict, reason: String) -> ReviewDecision {
    ReviewDecision {
        verdict,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: reason,
    }
}

fn print_decision_command_result(
    finding: &Finding,
    decision_id: i64,
    decision: &ReviewDecision,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&decision_result_json(finding, decision_id, decision))?
        );
    } else {
        println!(
            "decision saved; will carry forward as decision #{decision_id} ({})",
            decision.verdict.as_str()
        );
    }
    Ok(())
}

fn decision_result_json(
    finding: &Finding,
    decision_id: i64,
    decision: &ReviewDecision,
) -> serde_json::Value {
    json!({
        "decisionId": decision_id,
        "findingId": finding.id,
        "identityId": finding.identity_id.clone(),
        "fingerprint": finding.fingerprint.clone(),
        "verdict": decision.verdict.as_str(),
        "author": decision.author.as_str(),
        "reason": decision.rationale.clone(),
    })
}
