use crate::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use crate::proof::suppressions::{
    build_whitebox_suppression_for_finding, upsert_whitebox_suppression,
    WhiteboxSuppressionRecord,
};
use crate::suppressions::domain::{
    FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule,
};
use crate::suppressions::persistence::{derive_rule_id, upsert_suppression_rule};
use crate::workspace::record_user_review_decision_for_finding;
use crate::{Finding, WorkspaceTarget};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct FindingSuppressionRequest {
    pub reason: String,
    pub author: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct FindingSuppressionResult {
    pub record: WhiteboxSuppressionRecord,
    pub decision_id: i64,
    pub structured_rule_written: bool,
}

pub fn record_finding_suppression(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    request: FindingSuppressionRequest,
) -> Result<FindingSuppressionResult> {
    let record = build_whitebox_suppression_for_finding(
        workspace.root(),
        finding,
        request.reason.clone(),
        request.author.clone(),
        request.expires_at_unix,
    )?;
    let record = upsert_whitebox_suppression(workspace, record)?;
    let structured_rule_written = store_structured_rule(workspace, finding, &request)?;
    let decision_id = record_suppressed_decision(workspace, finding, &request.reason)?;
    Ok(FindingSuppressionResult {
        record,
        decision_id,
        structured_rule_written,
    })
}

fn store_structured_rule(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    request: &FindingSuppressionRequest,
) -> Result<bool> {
    let Some(reason) = SuppressionReason::parse(&request.reason) else {
        return Ok(false);
    };
    let predicate = SuppressionPredicate {
        finding_id: Some(FindingRef(finding.fingerprint.clone())),
        ..SuppressionPredicate::empty()
    };
    let rule = SuppressionRule {
        id: derive_rule_id(&predicate, reason),
        predicate,
        reason,
        statement: request.reason.clone(),
        actor: request.author.clone(),
        created_at_unix: now_unix(),
        expires_at_unix: Some(request.expires_at_unix),
        origin: SuppressionOrigin::File,
    };
    upsert_suppression_rule(workspace, rule)?;
    Ok(true)
}

fn record_suppressed_decision(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    reason: &str,
) -> Result<i64> {
    record_user_review_decision_for_finding(
        workspace,
        finding,
        &ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: reason.to_string(),
            dismiss_reason: None,
            actor: None,
        },
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
