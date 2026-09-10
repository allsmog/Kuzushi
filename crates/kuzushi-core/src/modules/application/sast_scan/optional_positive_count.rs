use super::*;
use crate::modules::autonomy::WorkflowPhase;

pub(in crate::modules) struct WhiteboxArtifactPaths {
    pub(in crate::modules) static_narratives: Option<String>,
    pub(in crate::modules) static_variants: Option<String>,
    pub(in crate::modules) candidate_semgrep_rules: Option<String>,
    pub(in crate::modules) whitebox_suppressions: Option<String>,
    pub(in crate::modules) whitebox_diff: Option<String>,
}

pub(in crate::modules) fn optional_positive_count(value: &Option<Value>, key: &str) -> Option<u64> {
    value
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)
}

pub(in crate::modules) fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

pub(in crate::modules) fn json_pointer_u64(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

pub(in crate::modules) fn artifact_path_if_present(
    value: &Option<Value>,
    artifacts: &SastRunArtifacts,
    filename: &str,
) -> Option<String> {
    value
        .as_ref()
        .map(|_| artifacts.dir.join(filename).display().to_string())
}

pub(in crate::modules) struct SastPostProcessing {
    pub(in crate::modules) triage: Option<Value>,
    pub(in crate::modules) verification_results: Vec<Value>,
    pub(in crate::modules) patch_results: Vec<Value>,
}

pub(in crate::modules) fn run_sast_post_processing(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<SastPostProcessing> {
    let triage = run_optional_sast_triage(
        registry,
        requests,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )?;
    let (verification_results, patch_results) = run_optional_sast_verification_and_patch(
        registry,
        requests,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )?;
    Ok(SastPostProcessing {
        triage,
        verification_results,
        patch_results,
    })
}

fn run_optional_sast_triage(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Option<Value>> {
    if !requests.triage {
        return Ok(None);
    }
    run_sast_triage(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
    )
    .map(Some)
}

fn run_optional_sast_verification_and_patch(
    registry: &ModuleRegistry,
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<(Vec<Value>, Vec<Value>)> {
    if !requests.needs_verification() {
        return Ok((Vec::new(), Vec::new()));
    }
    run_sast_verification_and_patch(
        registry,
        input,
        ctx,
        runtime,
        option_store,
        store,
        run_ids,
        artifacts,
        requests,
    )
}

pub(in crate::modules) fn run_sast_triage(
    registry: &ModuleRegistry,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let fingerprints = fingerprints_for_sast_runs(store, run_ids)?;
    let mut triage_input = if fingerprints.is_empty() {
        json!({ "scanId": run_ids.primary.clone() })
    } else {
        json!({ "fingerprints": fingerprints })
    };
    if let Some(reference) = input.get("threatModelRef") {
        triage_input["threatModelRef"] = reference.clone();
    }
    let triage_input =
        with_sast_prompt_override(triage_input, input, ctx, "triage", "TRIAGE_PROMPT")?;
    let output = run_sast_phase_subtool(
        registry,
        "triage:run",
        triage_input,
        ctx,
        runtime,
        option_store,
        artifacts,
        WorkflowPhase::Review,
        &run_ids.primary,
    )?;
    write_triage_jsonl(artifacts, &output)?;
    Ok(output)
}

pub(in crate::modules) fn run_sast_phase_subtool(
    registry: &ModuleRegistry,
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
    artifacts: &SastRunArtifacts,
    phase: WorkflowPhase,
    primary_run_id: &str,
) -> Result<Value> {
    let dispatched = dispatch_sast_subtool(registry, name, input, ctx, runtime, option_store);
    record_phase_dispatch(dispatched, name, artifacts, phase, primary_run_id)
}

pub(in crate::modules) fn dispatch_sast_subtool(
    registry: &ModuleRegistry,
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    option_store: &crate::options::ToolOptionStore,
) -> Result<Value> {
    let prepared = registry
        .prepare_dispatch_input(name, input, ctx, Some(option_store))?
        .authorize_delegated(&ctx.authorization);
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, runtime)
}

fn record_phase_dispatch(
    dispatched: Result<Value>,
    name: &str,
    artifacts: &SastRunArtifacts,
    phase: WorkflowPhase,
    primary_run_id: &str,
) -> Result<Value> {
    match dispatched {
        Ok(output) => {
            record_sast_phase_output(artifacts, phase, primary_run_id, &output)?;
            validate_sast_subtool_result(name, &output)?;
            Ok(output)
        }
        Err(error) => {
            let persistence = record_sast_phase_stage(
                artifacts,
                phase,
                SastPhaseStageOutcome::Failed,
                vec![primary_run_id.to_string()],
            );
            match persistence {
                Ok(()) => Err(error),
                Err(persistence) => Err(anyhow::anyhow!(
                    "{error:#}; additionally, phase receipt persistence failed: {persistence:#}"
                )),
            }
        }
    }
}

/// A subtool that stopped at a configured budget reports `partial` truthfully
/// and still hands back the work it did finish, so the pipeline keeps that
/// output and its partial phase receipt. Every other failure-like result ends
/// the run: a partial caused by an actual failure makes no such guarantee.
fn stopped_at_configured_budget(output: &Value) -> bool {
    crate::module_result::tool_result_status(output) == crate::module_result::ToolResultStatus::Partial
        && output.pointer("/data/stoppedAtBudget").and_then(Value::as_bool) == Some(true)
}

pub(in crate::modules) fn validate_sast_subtool_result(name: &str, output: &Value) -> Result<()> {
    if crate::module_result::tool_result_status(&output).is_failure_like()
        && !stopped_at_configured_budget(output)
    {
        let details = output
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!(
            "sast:scan subtool {name} did not complete successfully: {}",
            if details.is_empty() {
                output
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("subtool returned a failure-like result")
            } else {
                details.as_str()
            }
        );
    }
    Ok(())
}

#[cfg(test)]
mod result_truth_tests {
    use super::*;
    use crate::WorkspaceTarget;

    fn stage_artifacts(run_id: &str) -> (tempfile::TempDir, SastRunArtifacts) {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let artifacts = SastRunArtifacts::create(&workspace, run_id).unwrap();
        (target, artifacts)
    }

    #[test]
    fn failed_subtool_envelope_is_not_treated_as_success() {
        let output = json!({
            "ok": false,
            "status": "failed",
            "summary": "verify failed",
            "errors": ["runtime unavailable"]
        });

        let error = validate_sast_subtool_result("verify:finding", &output)
            .unwrap_err()
            .to_string();

        assert!(error.contains("runtime unavailable"));
    }

    #[test]
    fn skipped_subtool_envelope_remains_an_explicit_non_failure() {
        let output = json!({"ok": true, "status": "skipped"});

        validate_sast_subtool_result("triage:run", &output).unwrap();
    }

    #[test]
    fn partial_phase_subtool_cannot_be_mislabeled_as_complete() {
        let output = json!({"ok": true, "status": "partial", "data": {}});

        let error = validate_sast_subtool_result("verify:finding", &output).unwrap_err();

        assert!(error.to_string().contains("did not complete successfully"));
    }

    #[test]
    fn partial_stage_receipt_survives_outer_failure() {
        let (_target, artifacts) = stage_artifacts("scan-partial-stage");

        let error = record_phase_dispatch(
            Ok(json!({"ok": true, "status": "partial"})),
            "verify:finding",
            &artifacts,
            WorkflowPhase::Prove,
            "scan-partial-stage",
        )
        .unwrap_err();

        assert!(error.to_string().contains("did not complete successfully"));
        let stages = load_sast_phase_stages(&artifacts).unwrap();
        assert_eq!(stages[0]["phase"], "prove");
        assert_eq!(stages[0]["outcome"], "partial");
    }

    #[test]
    fn a_budget_stopped_partial_keeps_its_output_and_its_partial_receipt() {
        let (_target, artifacts) = stage_artifacts("scan-budget-stop");
        let output = json!({
            "ok": true,
            "status": "partial",
            "data": {"costCapHit": true, "pendingAfterCap": 3, "stoppedAtBudget": true}
        });

        let kept = record_phase_dispatch(
            Ok(output.clone()),
            "triage:run",
            &artifacts,
            WorkflowPhase::Review,
            "scan-budget-stop",
        )
        .unwrap();

        assert_eq!(kept, output);
        let stages = load_sast_phase_stages(&artifacts).unwrap();
        assert_eq!(stages[0]["outcome"], "partial");
    }

    #[test]
    fn a_partial_that_did_not_stop_at_a_budget_still_ends_the_run() {
        let output = json!({
            "ok": true,
            "status": "partial",
            "data": {"costCapHit": true, "pendingAfterCap": 3, "stoppedAtBudget": false},
            "errors": ["classification failed"]
        });

        let error = validate_sast_subtool_result("triage:run", &output).unwrap_err();

        assert!(error.to_string().contains("classification failed"));
    }

    #[test]
    fn a_failed_envelope_cannot_claim_a_budget_stop() {
        let output = json!({
            "ok": false,
            "status": "failed",
            "data": {"stoppedAtBudget": true},
            "errors": ["runtime unavailable"]
        });

        let error = validate_sast_subtool_result("triage:run", &output).unwrap_err();

        assert!(error.to_string().contains("runtime unavailable"));
    }

    #[test]
    fn transport_failure_persists_failed_stage_receipt() {
        let (_target, artifacts) = stage_artifacts("scan-failed-stage");

        let error = record_phase_dispatch(
            Err(anyhow::anyhow!("runtime disconnected")),
            "triage:run",
            &artifacts,
            WorkflowPhase::Review,
            "scan-failed-stage",
        )
        .unwrap_err();

        assert!(error.to_string().contains("runtime disconnected"));
        let stages = load_sast_phase_stages(&artifacts).unwrap();
        assert_eq!(stages[0]["phase"], "review");
        assert_eq!(stages[0]["outcome"], "failed");
    }
}
