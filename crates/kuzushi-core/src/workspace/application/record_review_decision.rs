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
    let finding_id = finding
        .id
        .context("review decision target has no persisted finding id")?;
    let read_watermark = match read_watermark {
        Some(read_watermark) => read_watermark,
        None => StorageWriterActor::commit_blocking(
            workspace.event_log_dir(),
            workspace.findings_db_path(),
            WriterCommand::Control(ControlCommand::Barrier),
        )?
        .committed_seq,
    };
    let stable_fp = finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone());
    let receipt = StorageWriterActor::commit_blocking(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        WriterCommand::Decision(DecisionCommand::ReviewDecision(DecisionWrite {
            stable_fp,
            finding_id: Some(finding_id),
            identity_id: finding.identity_id.clone(),
            verdict: decision.verdict.as_str().to_string(),
            author: decision.author.as_str().to_string(),
            rationale: decision.rationale.clone(),
            confidence_millis: (decision.confidence.clamp(0.0, 1.0) * 1000.0).round() as u16,
            read_watermark,
            updates_finding_triage: false,
        })),
    )?;
    Ok(receipt
        .projected_review_decision_id
        .unwrap_or(receipt.committed_seq as i64))
}
