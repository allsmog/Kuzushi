use crate::findings::{Finding, ReviewDecision};
use crate::storage_v3::writer_actor::{
    ControlCommand, DecisionCommand, DecisionWrite, StorageWriterActor, WriterCommand,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};

pub fn record_user_review_decision_for_finding(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    decision: &ReviewDecision,
) -> Result<i64> {
    record_user_review_decision_for_finding_at_watermark(workspace, finding, decision, None)
}

pub fn record_user_review_decision_for_finding_at_watermark(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    decision: &ReviewDecision,
    read_watermark: Option<u64>,
) -> Result<i64> {
    record_user_review_decision_for_finding_with_session(
        workspace,
        finding,
        decision,
        read_watermark,
        None,
    )
}

/// Records a verdict and, when one exists, the prospective review session it
/// concluded. The session id is carried, never derived: a decision taken
/// without a recorded session keeps `None` rather than being attached to the
/// nearest one.
pub fn record_user_review_decision_for_finding_with_session(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    decision: &ReviewDecision,
    read_watermark: Option<u64>,
    review_session_id: Option<String>,
) -> Result<i64> {
    let finding_id = finding
        .id
        .context("review decision target has no persisted finding id")?;
    let read_watermark = resolve_read_watermark(workspace, read_watermark)?;
    let write = review_decision_write(
        finding,
        decision,
        finding_id,
        read_watermark,
        review_session_id,
    );
    let receipt = StorageWriterActor::commit_blocking(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        WriterCommand::Decision(DecisionCommand::ReviewDecision(write)),
    )?;
    Ok(receipt
        .projected_review_decision_id
        .unwrap_or(receipt.committed_seq as i64))
}

fn resolve_read_watermark(workspace: &WorkspaceTarget, read_watermark: Option<u64>) -> Result<u64> {
    match read_watermark {
        Some(read_watermark) => Ok(read_watermark),
        None => Ok(StorageWriterActor::commit_blocking(
            workspace.event_log_dir(),
            workspace.findings_db_path(),
            WriterCommand::Control(ControlCommand::Barrier),
        )?
        .committed_seq),
    }
}

fn review_decision_write(
    finding: &Finding,
    decision: &ReviewDecision,
    finding_id: i64,
    read_watermark: u64,
    review_session_id: Option<String>,
) -> DecisionWrite {
    DecisionWrite {
        stable_fp: finding
            .identity_id
            .clone()
            .unwrap_or_else(|| finding.fingerprint.clone()),
        finding_id: Some(finding_id),
        identity_id: finding.identity_id.clone(),
        verdict: decision.verdict.as_str().to_string(),
        author: decision.author.as_str().to_string(),
        rationale: decision.rationale.clone(),
        confidence_millis: (decision.confidence.clamp(0.0, 1.0) * 1000.0).round() as u16,
        read_watermark,
        updates_finding_triage: false,
        triage_cost_usd: None,
        triage_cost_usd_exact: true,
        dismiss_reason: decision
            .dismiss_reason
            .map(|reason| reason.as_str().to_string()),
        dismissed_by: decision.actor.clone(),
        review_session_id,
    }
}
