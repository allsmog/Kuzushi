use super::canonical_run_files::record_report_artifacts;
use super::output_declared_artifacts::record_output_declared_artifacts;
use super::tool_run_failure_result::failed_tool_result_with_context;
use super::tool_run_record_events::append_started_event;
use super::*;
use crate::artifact_contract::{tool_input_artifact_spec, tool_result_artifact_spec};
use crate::module_result::{normalize_module_result, tool_result_status, ToolResultStatus};
use crate::run_lifecycle::RunItemStatus;
use crate::runtime::RuntimeCostReport;
use serde_json::json;

#[derive(Debug, Clone, Copy)]
pub struct ToolRunRecord<'a> {
    pub target: &'a Path,
    pub run_id: &'a str,
    pub kind: &'a str,
    pub tool: &'a str,
}

impl<'a> ToolRunRecord<'a> {
    pub fn new(target: &'a Path, run_id: &'a str, kind: &'a str, tool: &'a str) -> Self {
        Self {
            target,
            run_id,
            kind,
            tool,
        }
    }
}

pub fn record_tool_run_started(record: ToolRunRecord<'_>, input: &Value) {
    record_tool_run_started_with_metadata(record, input, None, None);
}

pub fn record_tool_run_started_with_metadata(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
) {
    record_tool_run_started_with_reproducibility(record, input, model, config_hash, Vec::new());
}

pub fn record_tool_run_started_with_reproducibility(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
    loaded_modules: Vec<String>,
) {
    let _ = try_record_tool_run_started_with_reproducibility(
        record,
        input,
        model,
        config_hash,
        loaded_modules,
    );
}

pub fn try_record_tool_run_started_with_reproducibility(
    record: ToolRunRecord<'_>,
    input: &Value,
    model: Option<String>,
    config_hash: Option<String>,
    loaded_modules: Vec<String>,
) -> Result<()> {
    let mut summary = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    )
    .with_process_id(std::process::id())
    .with_model(model)
    .with_config_hash(config_hash)
    .with_loaded_modules(loaded_modules);
    let input_artifact = input_artifact(record, input)?;
    summary = summary.with_artifact(input_artifact.clone());
    write_run_summary(record.target, &summary)?;
    append_started_event(record, Some(input_artifact))?;
    Ok(())
}

pub fn record_tool_run_complete(record: ToolRunRecord<'_>, output: &Value) {
    let _ = try_record_tool_run_complete(record, output);
}

pub fn try_record_tool_run_complete(record: ToolRunRecord<'_>, output: &Value) -> Result<()> {
    try_record_tool_run_complete_observed(record, output, None)
}

pub fn try_record_tool_run_complete_observed(
    record: ToolRunRecord<'_>,
    output: &Value,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_tool_run_complete_with_settlement(record, output, observation, None)
}

pub fn try_record_tool_run_complete_settled(
    record: ToolRunRecord<'_>,
    output: &Value,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_tool_run_complete_with_settlement(
        record,
        output,
        Some(observation),
        Some(completion),
    )
}

fn try_record_tool_run_complete_with_settlement(
    record: ToolRunRecord<'_>,
    output: &Value,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
) -> Result<()> {
    let (_guard, prepared, mut completion) =
        lock_and_prepare_terminal_result(record, observation, completion, true, || {
            prepare_completed_result(record, output)
        })?;
    let cost = completion
        .as_ref()
        .map_or(RuntimeCostReport::UNAVAILABLE, |pending| {
            pending.cost_report()
        });
    let (execution_status, execution_may_have_occurred) =
        completion_failure_context(&completion, true);
    let producing_call = settle_result_artifact(record, completion.take())?;
    if let Err(error) = persist_completed_summary(record, &prepared) {
        return fail_after_result_settlement(
            observation,
            record,
            producing_call,
            cost,
            execution_status,
            execution_may_have_occurred,
            error,
        );
    }
    emit_typed_terminal(observation, record, &prepared.output, producing_call)?;
    Ok(())
}

struct PreparedCompletedResult {
    status: &'static str,
    terminal_digest: String,
    output: Value,
    artifacts: Vec<RunArtifact>,
}

fn prepare_completed_result(
    record: ToolRunRecord<'_>,
    raw_output: &Value,
) -> Result<PreparedCompletedResult> {
    let status = tool_result_status_label(tool_result_status(raw_output));
    let normalized = normalize_module_result(raw_output.clone());
    let terminal_digest = terminal_result_digest(status, &normalized);
    validate_terminalization(record, status, &terminal_digest)?;
    let mut artifacts = existing_run_artifacts(record)?;
    artifacts.extend(record_output_declared_artifacts(
        record.target,
        record.run_id,
        raw_output,
        &artifacts,
    )?);
    artifacts.extend(record_report_artifacts(
        record.target,
        record.run_id,
        raw_output,
    )?);
    let output = result_output_for_status(record, status, raw_output, &mut artifacts)?;
    artifacts.push(result_artifact(record, &output)?);
    Ok(PreparedCompletedResult {
        status,
        terminal_digest,
        output,
        artifacts,
    })
}

fn persist_completed_summary(
    record: ToolRunRecord<'_>,
    prepared: &PreparedCompletedResult,
) -> Result<()> {
    let summary = completed_summary(record, &prepared.output, prepared.artifacts.clone())?;
    let summary = apply_output_status(prepared.status, summary, &prepared.output)
        .with_terminal_result_sha256(Some(prepared.terminal_digest.clone()));
    write_run_summary(record.target, &summary).map(|_| ())
}

pub fn record_tool_run_failed(record: ToolRunRecord<'_>, error: &str) {
    let _ = try_record_tool_run_failed(record, error);
}

pub fn try_record_tool_run_failed(record: ToolRunRecord<'_>, error: &str) -> Result<()> {
    try_record_tool_run_failed_observed(record, error, None)
}

pub fn try_record_tool_run_failed_observed(
    record: ToolRunRecord<'_>,
    error: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_tool_run_failed_observed_with_execution(record, error, observation, true)
}

pub fn try_record_tool_run_failed_observed_with_execution(
    record: ToolRunRecord<'_>,
    error: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    execution_may_have_occurred: bool,
) -> Result<()> {
    try_record_tool_run_failed_with_settlement(
        record,
        error,
        observation,
        None,
        execution_may_have_occurred,
    )
}

pub fn try_record_tool_run_failed_settled(
    record: ToolRunRecord<'_>,
    error: &str,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_tool_run_failed_with_settlement(
        record,
        error,
        Some(observation),
        Some(completion),
        true,
    )
}

fn try_record_tool_run_failed_with_settlement(
    record: ToolRunRecord<'_>,
    error: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred_without_completion: bool,
) -> Result<()> {
    let terminal_status = unsuccessful_terminal_status(
        completion.as_ref(),
        execution_may_have_occurred_without_completion,
    );
    let (_guard, prepared, mut completion) = lock_and_prepare_terminal_result(
        record,
        observation,
        completion,
        execution_may_have_occurred_without_completion,
        || prepare_unsuccessful_result(record, error, terminal_status),
    )?;
    let cost = completion
        .as_ref()
        .map_or(RuntimeCostReport::UNAVAILABLE, |pending| {
            pending.cost_report()
        });
    let (execution_status, execution_may_have_occurred) =
        completion_failure_context(&completion, execution_may_have_occurred_without_completion);
    let producing_call = settle_result_artifact(record, completion.take())?;
    if let Err(error) = write_run_summary(record.target, &prepared.summary) {
        return fail_after_result_settlement(
            observation,
            record,
            producing_call,
            cost,
            execution_status,
            execution_may_have_occurred,
            error,
        );
    }
    emit_typed_terminal(observation, record, &prepared.output, producing_call)?;
    Ok(())
}

fn lock_and_prepare_terminal_result<T>(
    record: ToolRunRecord<'_>,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred_without_completion: bool,
    prepare: impl FnOnce() -> Result<T>,
) -> Result<(
    crate::file_lock::ExclusiveFileLock,
    T,
    Option<crate::modules::PendingToolCallCompletion>,
)> {
    let guard = match super::run_ledger::acquire_run_terminal_lock(record.target, record.run_id) {
        Ok(guard) => guard,
        Err(error) => {
            return fail_before_result_settlement(
                observation,
                record,
                completion,
                execution_may_have_occurred_without_completion,
                error,
            );
        }
    };
    let prepared = match prepare() {
        Ok(prepared) => prepared,
        Err(error) => {
            return fail_before_result_settlement(
                observation,
                record,
                completion,
                execution_may_have_occurred_without_completion,
                error,
            );
        }
    };
    Ok((guard, prepared, completion))
}

fn unsuccessful_terminal_status(
    completion: Option<&crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred_without_completion: bool,
) -> RunItemStatus {
    match completion.map(crate::modules::PendingToolCallCompletion::terminal_status) {
        Some(RunItemStatus::Blocked) => RunItemStatus::Blocked,
        None if !execution_may_have_occurred_without_completion => RunItemStatus::Blocked,
        _ => RunItemStatus::Failed,
    }
}

struct PreparedUnsuccessfulResult {
    output: Value,
    summary: RunSummary,
}

fn prepare_unsuccessful_result(
    record: ToolRunRecord<'_>,
    error: &str,
    status: RunItemStatus,
) -> Result<PreparedUnsuccessfulResult> {
    let status = unsuccessful_status_label(status);
    let terminal_digest = terminal_result_digest(status, &json!({ "error": error }));
    validate_terminalization(record, status, &terminal_digest)?;
    let mut artifacts = existing_run_artifacts(record)?;
    let mut summary = unsuccessful_summary(record, error, &artifacts, status)?;
    let failure = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        status,
        error,
        &artifacts,
    )?;
    artifacts.push(failure.clone());
    summary = summary.with_artifact(failure);
    let mut output = failed_tool_result_with_context(
        record.target,
        record.run_id,
        record.tool,
        error,
        &artifacts,
    );
    set_unsuccessful_output_status(&mut output, record.tool, status);
    let result = result_artifact(record, &output)?;
    summary = summary
        .with_artifact(result)
        .with_terminal_result_sha256(Some(terminal_digest));
    Ok(PreparedUnsuccessfulResult { output, summary })
}

fn unsuccessful_status_label(status: RunItemStatus) -> &'static str {
    if status == RunItemStatus::Blocked {
        "blocked"
    } else {
        "failed"
    }
}

fn set_unsuccessful_output_status(output: &mut Value, tool: &str, status: &str) {
    let Some(object) = output.as_object_mut() else {
        return;
    };
    object.insert("status".to_string(), json!(status));
    if status == "blocked" {
        object.insert("summary".to_string(), json!(format!("{tool} blocked")));
    }
}

pub fn record_tool_run_canceled(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_canceled(record, reason);
}

pub fn try_record_tool_run_canceled(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    try_record_tool_run_canceled_observed(record, reason, None)
}

pub fn try_record_tool_run_canceled_observed(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_reason_terminal(record, "canceled", reason, observation, None, true)
}

pub fn try_record_tool_run_canceled_settled(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_reason_terminal(
        record,
        "canceled",
        reason,
        Some(observation),
        Some(completion),
        true,
    )
}

pub fn record_tool_run_interrupted(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_interrupted(record, reason);
}

pub fn try_record_tool_run_interrupted(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    try_record_tool_run_interrupted_observed(record, reason, None)
}

pub fn try_record_tool_run_interrupted_observed(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_reason_terminal(record, "interrupted", reason, observation, None, true)
}

pub fn try_record_tool_run_interrupted_settled(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_reason_terminal(
        record,
        "interrupted",
        reason,
        Some(observation),
        Some(completion),
        true,
    )
}

pub fn record_tool_run_refused(record: ToolRunRecord<'_>, reason: &str) {
    let _ = try_record_tool_run_refused(record, reason);
}

pub fn try_record_tool_run_refused(record: ToolRunRecord<'_>, reason: &str) -> Result<()> {
    try_record_tool_run_refused_observed(record, reason, None)
}

pub fn try_record_tool_run_refused_observed(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_reason_terminal(record, "skipped", reason, observation, None, false)
}

pub fn try_record_tool_run_refused_settled(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_reason_terminal(
        record,
        "skipped",
        reason,
        Some(observation),
        Some(completion),
        false,
    )
}

fn try_record_reason_terminal(
    record: ToolRunRecord<'_>,
    status: &'static str,
    reason: &str,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred: bool,
) -> Result<()> {
    let (_guard, prepared, completion) = lock_and_prepare_terminal_result(
        record,
        observation,
        completion,
        execution_may_have_occurred,
        || prepare_reason_terminal(record, status, reason),
    )?;
    if let Err(error) = write_run_summary(record.target, &prepared.summary) {
        return fail_before_result_settlement(
            observation,
            record,
            completion,
            execution_may_have_occurred,
            error,
        );
    }
    let producing_call = settle_call_without_result(completion)?;
    emit_typed_terminal(observation, record, &prepared.output, producing_call)?;
    Ok(())
}

struct PreparedReasonTerminal {
    output: Value,
    summary: RunSummary,
}

fn prepare_reason_terminal(
    record: ToolRunRecord<'_>,
    status: &'static str,
    reason: &str,
) -> Result<PreparedReasonTerminal> {
    let terminal_digest = terminal_result_digest(status, &json!({ "reason": reason }));
    validate_terminalization(record, status, &terminal_digest)?;
    let artifacts = existing_run_artifacts(record)?;
    let summary = reason_terminal_summary(record, status, reason)?;
    let summary = artifacts
        .into_iter()
        .fold(summary, RunSummary::with_artifact)
        .with_terminal_result_sha256(Some(terminal_digest));
    let output = terminal_reason_output(status, reason);
    Ok(PreparedReasonTerminal { output, summary })
}

fn reason_terminal_summary(
    record: ToolRunRecord<'_>,
    status: &str,
    reason: &str,
) -> Result<RunSummary> {
    let seed = summary_seed(record)?;
    if status == "skipped" {
        return Ok(seed.skipped(reason));
    }
    let summary = if status == "canceled" {
        seed.canceled(reason)
    } else {
        seed.interrupted(reason)
    };
    Ok(
        summary.with_cost_report(super::lifecycle_cost::lifecycle_cost_report(
            record.target,
            record.run_id,
        )?),
    )
}

fn settle_call_without_result(
    completion: Option<crate::modules::PendingToolCallCompletion>,
) -> Result<Option<crate::modules::ToolCallIdentity>> {
    let Some(completion) = completion else {
        return Ok(None);
    };
    let execution_may_have_occurred = completion.execution_may_have_occurred();
    completion
        .finish(None)
        .map_err(|error| annotate_writer_fault(error, execution_may_have_occurred))
}

fn emit_typed_terminal(
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    record: ToolRunRecord<'_>,
    output: &Value,
    producing_call: Option<crate::modules::ToolCallIdentity>,
) -> Result<()> {
    match observation {
        Some(observation) => crate::run_lifecycle::emit_persisted_terminal_outcome_for_call(
            observation,
            record.target,
            record.run_id,
            output,
            producing_call,
        ),
        None => {
            let observation = terminal_observation(record)?;
            crate::run_lifecycle::emit_persisted_terminal_outcome_for_call(
                &observation,
                record.target,
                record.run_id,
                output,
                producing_call,
            )
        }
    }
}

fn settle_result_artifact(
    record: ToolRunRecord<'_>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
) -> Result<Option<crate::modules::ToolCallIdentity>> {
    let Some(completion) = completion else {
        return Ok(None);
    };
    let execution_may_have_occurred = completion.execution_may_have_occurred();
    let identity = completion
        .identity()
        .context("observed tool completion has no call identity")?;
    let reference = crate::run_lifecycle::verified_result_artifact_reference(
        record.target,
        record.run_id,
        identity.item_id,
    )?;
    completion
        .finish(Some(reference))
        .map_err(|error| annotate_writer_fault(error, execution_may_have_occurred))?;
    Ok(Some(identity))
}

fn fail_before_result_settlement<T>(
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    record: ToolRunRecord<'_>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred_without_completion: bool,
    error: anyhow::Error,
) -> Result<T> {
    let execution_may_have_occurred = completion.as_ref().map_or(
        execution_may_have_occurred_without_completion,
        crate::modules::PendingToolCallCompletion::execution_may_have_occurred,
    );
    let error = annotate_writer_fault(error, execution_may_have_occurred);
    let Some(completion) = completion else {
        return Err(error);
    };
    let cost = completion.cost_report();
    let execution_status = completion.terminal_status();
    let detail = error.to_string();
    let identity = match completion.finish_after_persistence_failure(&detail) {
        Ok(identity) => identity,
        Err(settlement) => {
            let settlement = annotate_writer_fault(settlement, execution_may_have_occurred);
            return Err(error.context(format!(
                "typed call settlement also failed after dispatch resolution: {settlement}"
            )));
        }
    };
    fail_after_result_settlement(
        observation,
        record,
        identity,
        cost,
        execution_status,
        execution_may_have_occurred,
        error,
    )
}

fn completion_failure_context(
    completion: &Option<crate::modules::PendingToolCallCompletion>,
    execution_may_have_occurred_without_completion: bool,
) -> (crate::run_lifecycle::RunItemStatus, bool) {
    completion.as_ref().map_or(
        (
            crate::run_lifecycle::RunItemStatus::Failed,
            execution_may_have_occurred_without_completion,
        ),
        |pending| {
            (
                pending.terminal_status(),
                pending.execution_may_have_occurred(),
            )
        },
    )
}

fn fail_after_result_settlement<T>(
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    record: ToolRunRecord<'_>,
    identity: Option<crate::modules::ToolCallIdentity>,
    cost: RuntimeCostReport,
    execution_status: crate::run_lifecycle::RunItemStatus,
    execution_may_have_occurred: bool,
    error: anyhow::Error,
) -> Result<T> {
    let error = annotate_writer_fault(error, execution_may_have_occurred);
    let detail = error.to_string();
    if let (Some(observation), Some(identity)) = (observation, identity) {
        if let Err(settlement) = crate::run_lifecycle::emit_result_persistence_failure(
            observation,
            record.target,
            record.run_id,
            identity,
            &detail,
            cost,
            execution_status,
            execution_may_have_occurred,
        ) {
            return Err(error.context(format!(
                "terminal lifecycle settlement also failed: {settlement}"
            )));
        }
    }
    Err(error)
}

fn annotate_writer_fault(error: anyhow::Error, execution_may_have_occurred: bool) -> anyhow::Error {
    let Some(fault) = error
        .downcast_ref::<crate::run_lifecycle::RunItemWriterFault>()
        .cloned()
    else {
        return error;
    };
    anyhow::Error::new(fault.annotate_execution(execution_may_have_occurred))
}

fn terminal_observation(
    record: ToolRunRecord<'_>,
) -> Result<crate::run_lifecycle::RunObservationHandle> {
    crate::run_lifecycle::RunObservationHandle::jsonl(record.target, record.run_id)
}

fn terminal_reason_output(status: &str, reason: &str) -> Value {
    json!({
        "ok": status == "skipped",
        "status": status,
        "summary": reason,
        "output": "",
        "warnings": [],
        "errors": if status == "skipped" { Vec::<String>::new() } else { vec![reason.to_string()] },
        "artifacts": [],
        "data": {}
    })
}

pub fn tool_run_output_cost_usd(output: &Value) -> Option<f64> {
    tool_run_output_cost_report(output)
        .ok()
        .and_then(crate::runtime::RuntimeCostReport::exact_usd)
}

pub fn tool_run_output_findings_count(output: &Value) -> Option<u64> {
    output
        .pointer("/data/findingsCount")
        .or_else(|| output.get("findingsCount"))
        .or_else(|| output.pointer("/data/count"))
        .or_else(|| output.pointer("/data/totals/findings"))
        .and_then(Value::as_u64)
        .or_else(|| {
            output
                .pointer("/data/findings")
                .and_then(Value::as_array)
                .map(|findings| findings.len() as u64)
        })
}

#[cfg(test)]
#[path = "tool_run_record_settlement_tests.rs"]
mod settlement_tests;

fn tool_run_output_model(output: &Value) -> Option<String> {
    output
        .get("model")
        .or_else(|| output.pointer("/data/model"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn result_artifact(record: ToolRunRecord<'_>, output: &Value) -> Result<RunArtifact> {
    let spec = tool_result_artifact_spec("result.json")
        .expect("tool result artifact must be in shared spec");
    write_run_artifact_json(record.target, record.run_id, spec.leaf, spec.label, output)
}

fn input_artifact(record: ToolRunRecord<'_>, input: &Value) -> Result<RunArtifact> {
    let spec =
        tool_input_artifact_spec("input.json").expect("tool input artifact must be in shared spec");
    write_run_artifact_json(record.target, record.run_id, spec.leaf, spec.label, input)
}

fn completed_summary(
    record: ToolRunRecord<'_>,
    output: &Value,
    artifacts: Vec<RunArtifact>,
) -> Result<RunSummary> {
    let seed = summary_seed(record)?;
    let output_cost = tool_run_output_cost_report(output)?;
    let lifecycle_cost = super::lifecycle_cost::lifecycle_cost_report(record.target, record.run_id)?;
    let terminal_cost = super::lifecycle_cost::reconcile_terminal_cost_reports(
        output_cost,
        lifecycle_cost,
        "tool terminal",
    )?;
    let cost = super::lifecycle_cost::reconcile_terminal_cost_reports(
        seed.checked_cost_report()?,
        terminal_cost,
        "tool terminal seed",
    )?;
    let seed = seed
        .complete()
        .with_findings(tool_run_output_findings_count(output))
        .with_cost_report(cost);
    let seed = with_output_model(seed, output);
    Ok(artifacts.into_iter().fold(seed, RunSummary::with_artifact))
}

fn summary_seed(record: ToolRunRecord<'_>) -> Result<RunSummary> {
    let seed = RunSummary::running(
        record.run_id.to_string(),
        record.kind,
        Some(record.tool.to_string()),
        record.target.display().to_string(),
    );
    let existing =
        super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
            .with_context(|| {
                format!(
                    "could not load {} before terminalizing run {}",
                    run_artifact_path(record.target, record.run_id, "run.json").display(),
                    record.run_id,
                )
            })?;
    Ok(summary_seed_from_existing(seed, &existing))
}

fn summary_seed_from_existing(mut seed: RunSummary, existing: &RunSummary) -> RunSummary {
    seed.started_at_unix = existing.started_at_unix;
    seed.with_reproducibility_from(existing)
}

fn with_output_model(summary: RunSummary, output: &Value) -> RunSummary {
    let Some(model) = tool_run_output_model(output) else {
        return summary;
    };
    summary.with_model(Some(model))
}

fn result_output_for_status(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) -> Result<Value> {
    if failure_like_status(status) {
        attach_failure_artifact(record, status, output, artifacts)?;
        return Ok(normalize_module_result(output_with_run_fallback_context(
            record.target,
            record.run_id,
            output.clone(),
        )));
    }
    Ok(normalize_module_result(output.clone()))
}

fn apply_output_status(status: &str, mut summary: RunSummary, output: &Value) -> RunSummary {
    if failure_like_status(status) {
        summary.status = status.to_string();
        summary.error = Some(tool_run_output_error(output));
    }
    if status == "skipped" {
        summary.status = "skipped".to_string();
        summary.error = Some(tool_run_output_error(output));
    }
    summary
}

fn unsuccessful_summary(
    record: ToolRunRecord<'_>,
    error: &str,
    artifacts: &[RunArtifact],
    status: &str,
) -> Result<RunSummary> {
    let cost = super::lifecycle_cost::lifecycle_cost_report(record.target, record.run_id)?;
    let summary = summary_seed(record)?;
    let summary = if status == "blocked" {
        summary.blocked(error.to_string())
    } else {
        summary.failed(error.to_string())
    };
    Ok(artifacts.iter().cloned().fold(
        summary.with_cost_report(cost),
        RunSummary::with_artifact,
    ))
}

fn tool_result_status_label(status: ToolResultStatus) -> &'static str {
    match status {
        ToolResultStatus::Completed => "completed",
        ToolResultStatus::Partial => "partial",
        ToolResultStatus::Skipped => "skipped",
        ToolResultStatus::Failed => "failed",
    }
}

fn failure_like_status(status: &str) -> bool {
    matches!(status, "partial" | "failed")
}

fn validate_terminalization(
    record: ToolRunRecord<'_>,
    status: &str,
    terminal_digest: &str,
) -> Result<()> {
    let summary =
        super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
            .with_context(|| {
                format!(
                    "could not verify existing terminal state for run {} from {}",
                    record.run_id,
                    run_artifact_path(record.target, record.run_id, "run.json").display(),
                )
            })?;
    if !is_terminal_run_status(&summary.status) {
        return Ok(());
    }
    ensure_same_terminal_status(record, status, &summary)?;
    ensure_same_terminal_content(record, terminal_digest, &summary)
}

fn ensure_same_terminal_status(
    record: ToolRunRecord<'_>,
    status: &str,
    summary: &RunSummary,
) -> Result<()> {
    if summary.status != status {
        anyhow::bail!(
            "run {} is already terminal with status {}; refusing to rewrite it as {status}",
            record.run_id,
            summary.status
        )
    }
    Ok(())
}

fn ensure_same_terminal_content(
    record: ToolRunRecord<'_>,
    terminal_digest: &str,
    summary: &RunSummary,
) -> Result<()> {
    let Some(existing_digest) = summary.terminal_result_sha256.as_deref() else {
        anyhow::bail!(
            "run {} is already terminal but has no terminal result digest; refusing an unverifiable retry",
            record.run_id
        )
    };
    if existing_digest != terminal_digest {
        anyhow::bail!(
            "run {} is already terminal with different result content; refusing a divergent retry",
            record.run_id
        )
    }
    Ok(())
}

fn is_terminal_run_status(status: &str) -> bool {
    matches!(
        status,
        "completed"
            | "partial"
            | "skipped"
            | "blocked"
            | "failed"
            | "canceled"
            | "interrupted"
    )
}

fn existing_run_artifacts(record: ToolRunRecord<'_>) -> Result<Vec<RunArtifact>> {
    super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
        .map(|summary| summary.artifacts)
        .with_context(|| format!("could not load artifacts for run {}", record.run_id))
}

pub(crate) fn terminal_result_digest(status: &str, result: &Value) -> String {
    let bytes = serde_json::to_vec(&json!({
        "status": status,
        "result": result,
    }))
    .expect("terminal intent is always JSON serializable");
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes)
    )
}

pub fn tool_run_terminal_digest(output: &Value) -> String {
    let status = tool_result_status_label(tool_result_status(output));
    terminal_result_digest(status, &normalize_module_result(output.clone()))
}

fn attach_failure_artifact(
    record: ToolRunRecord<'_>,
    status: &str,
    output: &Value,
    artifacts: &mut Vec<RunArtifact>,
) -> Result<()> {
    let error = tool_run_output_error(output);
    let artifact = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        status,
        &error,
        artifacts,
    )?;
    artifacts.push(artifact);
    Ok(())
}

fn tool_run_output_error(output: &Value) -> String {
    output
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .or_else(|| output.get("error").and_then(Value::as_str))
        .or_else(|| output.get("summary").and_then(Value::as_str))
        .unwrap_or("module returned a non-completed status")
        .to_string()
}
