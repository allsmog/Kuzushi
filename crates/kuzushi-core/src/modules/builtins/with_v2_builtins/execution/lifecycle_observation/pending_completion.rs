use super::{PendingToolCallCompletion, ToolCallIdentity};
use crate::module_result::{tool_result_status, ToolResultStatus};
use crate::run_lifecycle::{
    ArtifactReference, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, SafeText,
};
use crate::runtime::RuntimeCostReport;
use anyhow::Result;
use serde_json::Value;

impl std::fmt::Debug for PendingToolCallCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingToolCallCompletion")
            .field("identity", &self.identity)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl PendingToolCallCompletion {
    /// Reuse the observation that owns this call's live writer when an
    /// application persists its terminal result. Opening another observation
    /// for the same run would contend on the writer's exclusive items lock.
    pub fn settlement_observation(&self) -> Option<crate::run_lifecycle::RunObservationHandle> {
        self.observation.clone()
    }

    pub fn identity(&self) -> Option<ToolCallIdentity> {
        self.identity
    }

    pub fn terminal_status(&self) -> RunItemStatus {
        self.status
    }

    pub fn cost_report(&self) -> RuntimeCostReport {
        self.cost
    }

    pub fn execution_may_have_occurred(&self) -> bool {
        self.execution_may_have_occurred
    }

    pub(crate) fn failure_source_snapshot(
        &self,
    ) -> Option<crate::workspace::source_snapshot::SourceSnapshot> {
        self.failure_source_snapshot.clone()
    }

    pub fn finish(
        self,
        result_artifact: Option<ArtifactReference>,
    ) -> Result<Option<ToolCallIdentity>> {
        let status = self.status;
        self.finish_with_status(status, result_artifact, None)
    }

    pub(crate) fn finish_as(
        self,
        status: RunItemStatus,
        result_artifact: Option<ArtifactReference>,
    ) -> Result<Option<ToolCallIdentity>> {
        self.finish_with_status(status, result_artifact, None)
    }

    pub fn finish_after_persistence_failure(
        self,
        detail: impl AsRef<str>,
    ) -> Result<Option<ToolCallIdentity>> {
        let status = persistence_failure_status(self.status);
        self.finish_with_status(status, None, Some(detail.as_ref()))
    }

    fn finish_with_status(
        mut self,
        status: RunItemStatus,
        result_artifact: Option<ArtifactReference>,
        persistence_failure: Option<&str>,
    ) -> Result<Option<ToolCallIdentity>> {
        validate_result_scope(result_artifact.as_ref(), self.identity)?;
        let Some((observation, identity)) = self.take_settlement_target() else {
            return Ok(None);
        };
        self.record_persistence_failure(persistence_failure);
        observation.emit_and_flush(self.finished_record(identity, status, result_artifact))?;
        Ok(Some(identity))
    }

    fn take_settlement_target(
        &mut self,
    ) -> Option<(crate::run_lifecycle::RunObservationHandle, ToolCallIdentity)> {
        Some((self.observation.take()?, self.identity?))
    }

    fn record_persistence_failure(&mut self, detail: Option<&str>) {
        let Some(detail) = detail else {
            return;
        };
        self.preview
            .truncate(crate::run_lifecycle::MAX_PREVIEW_LINES.saturating_sub(1));
        self.preview.push(SafeText::preview_line(format!(
            "semantic settlement incomplete: {detail}; do not retry automatically"
        )));
        self.error_count = self.error_count.saturating_add(1);
    }

    fn finished_record(
        &mut self,
        identity: ToolCallIdentity,
        status: RunItemStatus,
        result_artifact: Option<ArtifactReference>,
    ) -> RunItemRecord {
        RunItemRecord::new(
            identity.item_id,
            RunItemSource::Dispatch,
            RunItemV1::ToolCallFinished {
                status,
                cost: self.cost,
                result_artifact,
                preview: std::mem::take(&mut self.preview),
                warning_count: self.warning_count,
                error_count: self.error_count,
            },
        )
        .with_call(identity.call_id)
    }
}

fn validate_result_scope(
    artifact: Option<&ArtifactReference>,
    identity: Option<ToolCallIdentity>,
) -> Result<()> {
    let (Some(artifact), Some(identity)) = (artifact, identity) else {
        return Ok(());
    };
    anyhow::ensure!(
        artifact.producing_item_id == identity.item_id,
        "result artifact is scoped to a different call"
    );
    Ok(())
}

fn persistence_failure_status(status: RunItemStatus) -> RunItemStatus {
    match status {
        RunItemStatus::Failed => RunItemStatus::Failed,
        _ => RunItemStatus::Partial,
    }
}

#[cfg(test)]
mod persistence_failure_tests {
    use super::*;

    #[test]
    fn persistence_failure_keeps_terminal_preview_within_the_lifecycle_limit() {
        let mut pending = PendingToolCallCompletion {
            observation: None,
            identity: None,
            status: RunItemStatus::Completed,
            cost: RuntimeCostReport::UNAVAILABLE,
            preview: (0..crate::run_lifecycle::MAX_PREVIEW_LINES)
                .map(|line| SafeText::preview_line(format!("output {line}")))
                .collect(),
            warning_count: 0,
            error_count: 0,
            execution_may_have_occurred: true,
            failure_source_snapshot: None,
        };
        pending.record_persistence_failure(Some("declared artifact missing"));
        assert_eq!(
            pending.preview.len(),
            crate::run_lifecycle::MAX_PREVIEW_LINES
        );
        assert_eq!(pending.error_count, 1);
        assert!(pending
            .preview
            .last()
            .unwrap()
            .as_str()
            .contains("do not retry automatically"));
        let identity = ToolCallIdentity {
            item_id: crate::run_lifecycle::RunItemId::new(),
            call_id: crate::run_lifecycle::RunCallId::new(),
            task_id: None,
            parent_item_id: None,
        };
        let record = pending.finished_record(identity, RunItemStatus::Partial, None);
        crate::run_lifecycle::RunItemEnvelopeV1::from_record(
            1,
            crate::run_lifecycle::RunId::parse("preview-limit").unwrap(),
            record,
            None,
        )
        .unwrap();
    }
}

pub(super) fn result_fields(
    result: &Result<Value>,
) -> (RunItemStatus, RuntimeCostReport, Vec<SafeText>, u64, u64) {
    let output = match result {
        Ok(output) => output,
        Err(error) => return failed_result_fields(error),
    };
    let cost = crate::run_artifacts::tool_run_output_cost_report(output)
        .unwrap_or(RuntimeCostReport::UNAVAILABLE);
    (
        lifecycle_status(tool_result_status(output)),
        cost,
        result_preview(output),
        message_count(output, "warnings"),
        message_count(output, "errors"),
    )
}

/// A failed tool may still have paid for model calls. A structured-output
/// failure carries what it observed (including a labelled estimate); any other
/// error has no receipt. A policy refusal raised before any work ran (such as
/// a missing model) is `blocked`, not `failed`.
fn failed_result_fields(
    error: &anyhow::Error,
) -> (RunItemStatus, RuntimeCostReport, Vec<SafeText>, u64, u64) {
    let cost = error
        .chain()
        .find_map(|source| source.downcast_ref::<crate::structured_output::StructuredOutputError>())
        .map_or(RuntimeCostReport::UNAVAILABLE, |failure| {
            failure.cost_report()
        });
    let status = if crate::runtime::is_pre_execution_refusal(error) {
        RunItemStatus::Blocked
    } else {
        RunItemStatus::Failed
    };
    (status, cost, Vec::new(), 0, 1)
}

fn lifecycle_status(status: ToolResultStatus) -> RunItemStatus {
    match status {
        ToolResultStatus::Completed => RunItemStatus::Completed,
        ToolResultStatus::Partial => RunItemStatus::Partial,
        ToolResultStatus::Skipped => RunItemStatus::Skipped,
        ToolResultStatus::Failed => RunItemStatus::Failed,
    }
}

fn result_preview(output: &Value) -> Vec<SafeText> {
    output
        .get("summary")
        .and_then(Value::as_str)
        .into_iter()
        .flat_map(str::lines)
        .chain(output_lines(output))
        .filter(|line| !line.trim().is_empty())
        .take(crate::run_lifecycle::MAX_PREVIEW_LINES)
        .map(SafeText::preview_line)
        .collect()
}

fn output_lines(output: &Value) -> impl Iterator<Item = &str> {
    output
        .get("output")
        .and_then(Value::as_str)
        .into_iter()
        .flat_map(str::lines)
}

fn message_count(output: &Value, field: &str) -> u64 {
    output
        .get(field)
        .and_then(Value::as_array)
        .map_or(0, |messages| messages.len() as u64)
}

#[cfg(test)]
mod failed_cost_tests {
    use super::*;
    use crate::runtime::RuntimeCost;

    #[test]
    fn a_failed_structured_output_keeps_its_observed_estimate() {
        let estimate = RuntimeCost::from_usd(0.17, "cost").unwrap();
        let observed = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(estimate));
        let error = anyhow::Error::from(
            crate::structured_output::StructuredOutputError::from_source_and_cost(
                anyhow::anyhow!("invalid"),
                observed,
            ),
        )
        .context("verify:finding failed");

        let (status, cost, ..) = result_fields(&Err(error));

        assert_eq!(status, RunItemStatus::Failed);
        assert_eq!(cost.estimated_total_usd(), Some(0.17));
        let (_, plain_cost, ..) = result_fields(&Err(anyhow::anyhow!("no model call")));
        assert!(plain_cost.is_unavailable());
    }
}
