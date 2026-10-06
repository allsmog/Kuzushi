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
    summary = super::threat_model_context::bind_summary_context(record.target, input, summary)?;
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
    let failure_context = settlement_failure_context(completion.as_ref());
    let producing_call = settle_result_artifact(record, completion.take())?;
    let summary = after_result_settlement(
        completed_summary_for_prepared(record, &prepared),
        observation,
        record,
        producing_call,
        failure_context,
    )?;
    persist_terminal_after_settlement(
        record,
        observation,
        &prepared.output,
        &summary,
        producing_call,
        failure_context,
    )
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

fn completed_summary_for_prepared(
    record: ToolRunRecord<'_>,
    prepared: &PreparedCompletedResult,
) -> Result<RunSummary> {
    let summary = completed_summary(record, &prepared.output, prepared.artifacts.clone())?;
    Ok(
        apply_output_status(prepared.status, summary, &prepared.output)
            .with_terminal_result_sha256(Some(prepared.terminal_digest.clone())),
    )
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
    let source = completion
        .as_ref()
        .and_then(crate::modules::PendingToolCallCompletion::failure_source_snapshot);
    let (_guard, prepared, mut completion) = lock_and_prepare_terminal_result(
        record,
        observation,
        completion,
        execution_may_have_occurred_without_completion,
        || prepare_unsuccessful_result(record, error, terminal_status, source.as_ref()),
    )?;
    let failure_context = settlement_failure_context(completion.as_ref());
    let producing_call = settle_result_artifact(record, completion.take())?;
    persist_terminal_after_settlement(
        record,
        observation,
        &prepared.output,
        &prepared.summary,
        producing_call,
        failure_context,
    )
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
    source: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
) -> Result<PreparedUnsuccessfulResult> {
    let error = crate::session_transcript::redaction::redact_text(error);
    let status = unsuccessful_status_label(status);
    let context = super::scan_failure_context::attach(record, json!({ "error": &error }))?;
    let terminal_digest =
        terminal_result_digest(status, &with_failure_source(context.clone(), source));
    validate_terminalization(record, status, &terminal_digest)?;
    let mut artifacts = existing_run_artifacts(record)?;
    let mut summary = unsuccessful_summary(record, &error, &artifacts, status)?
        .with_findings(tool_run_output_findings_count(&context));
    let failure = write_run_failures(
        record.target,
        record.run_id,
        record.tool,
        status,
        &error,
        &artifacts,
    )?;
    artifacts.push(failure.clone());
    summary = summary.with_artifact(failure);
    let output = unsuccessful_output(record, &error, &artifacts, status, source)?;
    let result = result_artifact(record, &output)?;
    summary = summary
        .with_artifact(result)
        .with_terminal_result_sha256(Some(terminal_digest));
    Ok(PreparedUnsuccessfulResult { output, summary })
}

fn unsuccessful_output(
    record: ToolRunRecord<'_>,
    error: &str,
    artifacts: &[RunArtifact],
    status: &str,
    source: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
) -> Result<Value> {
    let mut output = failed_tool_result_with_context(
        record.target,
        record.run_id,
        record.tool,
        error,
        artifacts,
    );
    set_unsuccessful_output_status(&mut output, record.tool, status);
    let output = super::scan_failure_context::attach(record, output)?;
    Ok(with_failure_source(output, source))
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
    try_record_reason_terminal(record, "blocked", reason, observation, None, false)
}

pub fn try_record_tool_run_refused_settled(
    record: ToolRunRecord<'_>,
    reason: &str,
    observation: &crate::run_lifecycle::RunObservationHandle,
    completion: crate::modules::PendingToolCallCompletion,
) -> Result<()> {
    try_record_reason_terminal(
        record,
        "blocked",
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
    let source = completion
        .as_ref()
        .and_then(crate::modules::PendingToolCallCompletion::failure_source_snapshot);
    let (_guard, prepared, completion) = lock_and_prepare_terminal_result(
        record,
        observation,
        completion,
        execution_may_have_occurred,
        || prepare_reason_terminal(record, status, reason, source.as_ref()),
    )?;
    let failure_context = settlement_failure_context(completion.as_ref());
    let producing_call = settle_reason_result(record, completion, reason_terminal_status(status)?)?;
    persist_terminal_after_settlement(
        record,
        observation,
        &prepared.output,
        &prepared.summary,
        producing_call,
        failure_context,
    )
}

struct PreparedReasonTerminal {
    output: Value,
    summary: RunSummary,
}

fn prepare_reason_terminal(
    record: ToolRunRecord<'_>,
    status: &'static str,
    reason: &str,
    source: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
) -> Result<PreparedReasonTerminal> {
    let context = super::scan_failure_context::attach(record, json!({ "reason": reason }))?;
    let terminal_digest = terminal_result_digest(status, &with_failure_source(context, source));
    let output =
        super::scan_failure_context::attach(record, terminal_reason_output(status, reason))?;
    let output = with_failure_source(output, source);
    validate_terminalization(record, status, &terminal_digest)?;
    let artifacts = existing_run_artifacts(record)?;
    let summary = reason_terminal_summary(record, status, reason)?
        .with_findings(tool_run_output_findings_count(&output));
    let result = result_artifact(record, &output)?;
    let summary = artifacts
        .into_iter()
        .fold(summary, RunSummary::with_artifact)
        .with_artifact(result)
        .with_terminal_result_sha256(Some(terminal_digest));
    Ok(PreparedReasonTerminal { output, summary })
}

fn with_failure_source(
    mut output: Value,
    source: Option<&crate::workspace::source_snapshot::SourceSnapshot>,
) -> Value {
    let Some(source) = source else {
        return output;
    };
    if !output["data"].is_object() {
        output["data"] = json!({});
    }
    source.clone().attach(output)
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
    let summary = match status {
        "blocked" => seed.blocked(reason),
        "canceled" => seed.canceled(reason),
        "interrupted" => seed.interrupted(reason),
        other => anyhow::bail!("unsupported reason terminal status {other:?}"),
    };
    Ok(
        summary.with_cost_report(super::lifecycle_cost::lifecycle_cost_report(
            record.target,
            record.run_id,
        )?),
    )
}

fn settle_reason_result(
    record: ToolRunRecord<'_>,
    completion: Option<crate::modules::PendingToolCallCompletion>,
    status: crate::run_lifecycle::RunItemStatus,
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
        .finish_as(status, Some(reference))
        .map_err(|error| annotate_writer_fault(error, execution_may_have_occurred))
}

fn reason_terminal_status(status: &str) -> Result<crate::run_lifecycle::RunItemStatus> {
    use crate::run_lifecycle::RunItemStatus;
    match status {
        "blocked" => Ok(RunItemStatus::Blocked),
        "canceled" => Ok(RunItemStatus::Canceled),
        "interrupted" => Ok(RunItemStatus::Interrupted),
        "skipped" => Ok(RunItemStatus::Skipped),
        other => anyhow::bail!("unsupported reason terminal status {other:?}"),
    }
}

fn persist_terminal_after_settlement(
    record: ToolRunRecord<'_>,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    output: &Value,
    summary: &RunSummary,
    producing_call: Option<crate::modules::ToolCallIdentity>,
    failure_context: Option<SettlementFailureContext>,
) -> Result<()> {
    after_result_settlement(
        super::terminal_intent::write_terminal_intent(record.target, summary),
        observation,
        record,
        producing_call,
        failure_context,
    )?;
    after_result_settlement(
        emit_typed_terminal(observation, record, output, summary, producing_call),
        observation,
        record,
        producing_call,
        failure_context,
    )?;
    super::terminal_intent::mark_typed_terminal(record.target, record.run_id)?;
    write_run_summary(record.target, summary)?;
    super::terminal_intent::clear_terminal_intent_best_effort(record.target, record.run_id);
    Ok(())
}

fn emit_typed_terminal(
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    record: ToolRunRecord<'_>,
    output: &Value,
    summary: &RunSummary,
    producing_call: Option<crate::modules::ToolCallIdentity>,
) -> Result<()> {
    match observation {
        Some(observation) => crate::run_lifecycle::emit_terminal_outcome_for_summary(
            observation,
            record.target,
            record.run_id,
            output,
            summary,
            producing_call,
        ),
        None => {
            let observation = terminal_observation(record)?;
            crate::run_lifecycle::emit_terminal_outcome_for_summary(
                &observation,
                record.target,
                record.run_id,
                output,
                summary,
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

#[derive(Clone, Copy)]
struct SettlementFailureContext {
    cost: RuntimeCostReport,
    execution_status: crate::run_lifecycle::RunItemStatus,
    execution_may_have_occurred: bool,
}

fn settlement_failure_context(
    completion: Option<&crate::modules::PendingToolCallCompletion>,
) -> Option<SettlementFailureContext> {
    completion.map(|pending| SettlementFailureContext {
        cost: pending.cost_report(),
        execution_status: pending.terminal_status(),
        execution_may_have_occurred: pending.execution_may_have_occurred(),
    })
}

fn after_result_settlement<T>(
    result: Result<T>,
    observation: Option<&crate::run_lifecycle::RunObservationHandle>,
    record: ToolRunRecord<'_>,
    identity: Option<crate::modules::ToolCallIdentity>,
    context: Option<SettlementFailureContext>,
) -> Result<T> {
    match (result, context) {
        (Ok(value), _) => Ok(value),
        (Err(error), None) => Err(error),
        (Err(error), Some(context)) => fail_after_result_settlement(
            observation,
            record,
            identity,
            context.cost,
            context.execution_status,
            context.execution_may_have_occurred,
            error,
        ),
    }
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

#[cfg(test)]
#[path = "tool_run_record_source_failure_tests.rs"]
mod source_failure_tests;

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
    let lifecycle_cost =
        super::lifecycle_cost::lifecycle_cost_report(record.target, record.run_id)?;
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
    let mut result = if failure_like_status(status) {
        attach_failure_artifact(record, status, output, artifacts)?;
        normalize_module_result(output_with_run_fallback_context(
            record.target,
            record.run_id,
            output.clone(),
        ))
    } else {
        normalize_module_result(output.clone())
    };
    if let Some(object) = result.as_object_mut() {
        let mut listed = artifacts.clone();
        let spec = tool_result_artifact_spec("result.json")
            .expect("tool result artifact must be in shared spec");
        let result_artifact = RunArtifact::from_declared(spec.label, spec.leaf, Some(spec.kind))
            .expect("tool result artifact spec is valid");
        if !listed
            .iter()
            .any(|known| known.path == result_artifact.path)
        {
            listed.push(result_artifact);
        }
        object.insert("artifacts".to_string(), serde_json::to_value(listed)?);
    }
    Ok(result)
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
    Ok(artifacts
        .iter()
        .cloned()
        .fold(summary.with_cost_report(cost), RunSummary::with_artifact))
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
        "completed" | "partial" | "skipped" | "blocked" | "failed" | "canceled" | "interrupted"
    )
}

fn existing_run_artifacts(record: ToolRunRecord<'_>) -> Result<Vec<RunArtifact>> {
    let mut artifacts =
        super::run_summary_store::load_run_summary_without_repair(record.target, record.run_id)
            .map(|summary| summary.artifacts)
            .with_context(|| format!("could not load artifacts for run {}", record.run_id))?;
    for artifact in super::load_run_artifacts(record.target, record.run_id)? {
        if !artifacts.iter().any(|known| known.path == artifact.path) {
            artifacts.push(artifact);
        }
    }
    Ok(artifacts)
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
    let summary = output
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_str)
        .or_else(|| output.get("error").and_then(Value::as_str))
        .or_else(|| output.get("summary").and_then(Value::as_str))
        .unwrap_or("module returned a non-completed status")
        .to_string();
    match partial_scan_omission_preview(output) {
        Some(omissions) => format!("{summary}\nIncomplete coverage: {omissions}"),
        None => summary,
    }
}

fn partial_scan_omission_preview(output: &Value) -> Option<String> {
    if tool_result_status(output) != ToolResultStatus::Partial {
        return None;
    }
    let errors = output.pointer("/data/scanErrors")?.as_array()?;
    let mut previews = errors
        .iter()
        .filter_map(Value::as_str)
        .take(3)
        .map(bounded_omission_preview)
        .collect::<Vec<_>>();
    if previews.is_empty() {
        return None;
    }
    if errors.len() > previews.len() {
        previews.push(format!(
            "{} more reported omissions; open the run for details",
            errors.len() - previews.len()
        ));
    }
    Some(previews.join("; "))
}

fn bounded_omission_preview(error: &str) -> String {
    let mut chars = error
        .lines()
        .next()
        .unwrap_or("unspecified omission")
        .chars();
    let mut preview = chars.by_ref().take(240).collect::<String>();
    if chars.next().is_some() || error.contains('\n') {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod coverage_error_tests;

#[cfg(test)]
#[path = "tool_run_record/retention_digest_tests.rs"]
mod retention_digest_tests;
