use super::{
    FindingDeltaSummary, RunItemStatus, RunItemV1, MAX_ARTIFACT_REFERENCES, MAX_FINDING_ID_SAMPLES,
    MAX_PREVIEW_LINES, MAX_PREVIEW_LINE_CHARS, RUN_ITEM_REDACTION_POLICY_VERSION,
};
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceClass {
    Lossless,
    Coalescible,
}

pub struct RunItemPersistencePolicy;

impl RunItemPersistencePolicy {
    pub fn class(item: &RunItemV1) -> PersistenceClass {
        match item {
            RunItemV1::ToolCallProgress { .. } | RunItemV1::SafeReasoningSummary { .. } => {
                PersistenceClass::Coalescible
            }
            RunItemV1::PlanUpdated { .. }
            | RunItemV1::TaskUpdated { .. }
            | RunItemV1::ToolCallRequested { .. }
            | RunItemV1::ToolCallRejected { .. }
            | RunItemV1::ToolCallStarted { .. }
            | RunItemV1::ToolCallFinished { .. }
            | RunItemV1::ModelCallStarted { .. }
            | RunItemV1::ModelCallFinished { .. }
            | RunItemV1::ArtifactProduced { .. }
            | RunItemV1::FindingDelta { .. }
            | RunItemV1::OperatorQuestion { .. }
            | RunItemV1::OperatorDecision { .. }
            | RunItemV1::DiagnosticNotice { .. }
            | RunItemV1::TerminalOutcome { .. }
            | RunItemV1::PhaseReceipt { .. }
            | RunItemV1::ProgressTruncated { .. } => PersistenceClass::Lossless,
        }
    }

    pub fn validate(item: &RunItemV1) -> Result<()> {
        match item {
            RunItemV1::PlanUpdated { .. }
            | RunItemV1::ToolCallRequested { .. }
            | RunItemV1::OperatorQuestion { .. } => validate_collection_bounds(item)?,
            RunItemV1::ToolCallFinished {
                status, preview, ..
            } => validate_tool_call_finish(*status, preview)?,
            RunItemV1::ModelCallFinished { status, .. } => {
                ensure_terminal(*status, "model call")?;
            }
            RunItemV1::SafeReasoningSummary {
                redaction_policy_version,
                ..
            } => anyhow::ensure!(
                *redaction_policy_version == RUN_ITEM_REDACTION_POLICY_VERSION,
                "unsupported reasoning-summary redaction policy"
            ),
            RunItemV1::FindingDelta { delta } => validate_finding_delta(delta)?,
            RunItemV1::TerminalOutcome { status, .. } => {
                ensure_terminal(*status, "run outcome")?;
            }
            RunItemV1::PhaseReceipt { .. } => validate_phase_receipt(item)?,
            RunItemV1::ProgressTruncated { omitted_count, .. } => {
                anyhow::ensure!(*omitted_count > 0, "truncation count must be positive");
            }
            RunItemV1::TaskUpdated { .. }
            | RunItemV1::ToolCallRejected { .. }
            | RunItemV1::ToolCallStarted { .. }
            | RunItemV1::ToolCallProgress { .. }
            | RunItemV1::ModelCallStarted { .. }
            | RunItemV1::ArtifactProduced { .. }
            | RunItemV1::OperatorDecision { .. }
            | RunItemV1::DiagnosticNotice { .. } => {}
        }
        Ok(())
    }
}

fn validate_collection_bounds(item: &RunItemV1) -> Result<()> {
    match item {
        RunItemV1::PlanUpdated { task_ids, .. } => {
            anyhow::ensure!(task_ids.len() <= 2_048, "plan task list is too large");
            Ok(())
        }
        RunItemV1::ToolCallRequested {
            safe_option_names, ..
        } => validate_len(safe_option_names.len(), 128, "safe option names"),
        RunItemV1::OperatorQuestion { choices, .. } => {
            validate_len(choices.len(), 16, "operator choices")
        }
        _ => unreachable!("collection validator received another item"),
    }
}

fn validate_tool_call_finish(status: RunItemStatus, preview: &[super::SafeText]) -> Result<()> {
    ensure_terminal(status, "tool call")?;
    validate_len(preview.len(), MAX_PREVIEW_LINES, "preview lines")?;
    anyhow::ensure!(
        preview
            .iter()
            .all(|line| line.as_str().chars().count() <= MAX_PREVIEW_LINE_CHARS),
        "preview line exceeds maximum {MAX_PREVIEW_LINE_CHARS}"
    );
    Ok(())
}

fn validate_phase_receipt(item: &RunItemV1) -> Result<()> {
    let RunItemV1::PhaseReceipt {
        status,
        run_ids,
        artifact_ids,
        finding_delta,
        offered_actions,
        ..
    } = item
    else {
        unreachable!("phase receipt validator received another item")
    };
    ensure_terminal(*status, "phase receipt")?;
    validate_len(run_ids.len(), 64, "receipt run references")?;
    validate_len(
        artifact_ids.len(),
        MAX_ARTIFACT_REFERENCES,
        "receipt artifacts",
    )?;
    validate_len(offered_actions.len(), 16, "receipt actions")?;
    validate_finding_delta(finding_delta)
}

fn ensure_terminal(status: RunItemStatus, context: &str) -> Result<()> {
    anyhow::ensure!(status.is_terminal(), "{context} requires a terminal status");
    Ok(())
}

fn validate_finding_delta(delta: &FindingDeltaSummary) -> Result<()> {
    validate_len(
        delta.finding_id_samples.len(),
        MAX_FINDING_ID_SAMPLES,
        "finding samples",
    )
}

fn validate_len(actual: usize, maximum: usize, context: &str) -> Result<()> {
    anyhow::ensure!(actual <= maximum, "{context} exceeds maximum {maximum}");
    Ok(())
}
