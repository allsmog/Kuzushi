use super::*;

pub fn run_patch_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let resources = patch_resources(ctx)?;
    let raw_input = input;
    let input = PatchFindingInput::from_tool_input(&raw_input)?;
    let parent_step = emit_patch_start(ctx, &input);
    emit_patch_progress(ctx, parent_step, "finding · confirm patch candidate");
    let candidate = match confirmed_patch_candidate(resources.store, &input)? {
        PatchCandidateLookup::Ready(candidate) => candidate,
        PatchCandidateLookup::Refused(response) => return Ok(response),
    };
    let provenance = patch_provenance(
        ctx,
        resources.workspace.root(),
        &candidate.finding,
        &input.source_commit,
    )?;
    emit_patch_progress(ctx, parent_step, "execution · use approved validation plan");
    let execution = patch_execution(ctx, runtime, resources.workspace.root(), &input, &raw_input)?;
    let attempts = run_patch_attempts(
        ctx,
        parent_step,
        resources.workspace.root(),
        &execution,
        &candidate,
        &input,
    )?;
    finish_patch_finding(
        ctx,
        parent_step,
        &resources,
        &candidate,
        &execution,
        attempts,
        provenance,
    )
}

fn finish_patch_finding(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    resources: &PatchResources<'_>,
    candidate: &ConfirmedPatchFinding,
    execution: &PatchExecution<'_>,
    attempts: PatchAttemptOutcome,
    provenance: PatchProvenance,
) -> Result<Value> {
    let validator_log = patch_validator_log(&attempts.history);
    let final_explanation = attempts.final_explanation.clone();
    let result = patch_result(
        &candidate,
        &execution,
        attempts,
        validator_log.clone(),
        provenance,
    );
    emit_patch_progress(ctx, parent_step, "persist · save patch result");
    resources.store.insert_patch_result(&result)?;
    emit_patch_done(ctx, &result);
    patch_result_to_tool_json(
        &candidate.finding.fingerprint,
        &result,
        &validator_log,
        final_explanation.as_deref(),
    )
}

struct PatchResources<'a> {
    workspace: &'a crate::workspace::WorkspaceTarget,
    store: &'a crate::findings::FindingStore,
}

fn patch_resources<'a>(ctx: &'a ToolExecutionContext<'a>) -> Result<PatchResources<'a>> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "patch:finding",
        ))?;
    let store = ctx
        .findings_store
        .context("patch:finding requires a findings store for the active workspace")?;
    Ok(PatchResources { workspace, store })
}

fn emit_patch_start(ctx: &ToolExecutionContext<'_>, input: &PatchFindingInput) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "finding",
                format!("patch:finding start · fp={}", input.fingerprint),
            )
            .emit()
    })
}

fn emit_patch_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", "finding", label.into())
        .emit();
}

struct ConfirmedPatchFinding {
    finding: Finding,
    triage: TriageOutcome,
}

enum PatchCandidateLookup {
    Ready(ConfirmedPatchFinding),
    Refused(Value),
}

fn confirmed_patch_candidate(
    store: &crate::findings::FindingStore,
    input: &PatchFindingInput,
) -> Result<PatchCandidateLookup> {
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(PatchCandidateLookup::Refused(
            super::patch_refusal_response::missing_patch_finding_response(&input.fingerprint),
        ));
    };
    let Some(triage) = finding.triage.clone() else {
        return Ok(PatchCandidateLookup::Refused(
            super::patch_refusal_response::untriaged_patch_finding_response(&finding.fingerprint),
        ));
    };
    if triage.verdict != TriageVerdict::TruePositive {
        return Ok(PatchCandidateLookup::Refused(
            super::patch_refusal_response::unconfirmed_patch_finding_response(&finding.fingerprint),
        ));
    }
    Ok(PatchCandidateLookup::Ready(ConfirmedPatchFinding {
        finding,
        triage,
    }))
}

struct PatchExecution<'a> {
    runtime: &'a dyn AgentRuntime,
    model: String,
    prompt_override: Option<String>,
    source_commit: String,
    plan: PatchValidationPlan,
    repo_name: String,
    style: PatchStyle,
    validation_timeout: std::time::Duration,
}

fn patch_execution<'a>(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
    repo_root: &Path,
    input: &PatchFindingInput,
    raw_input: &Value,
) -> Result<PatchExecution<'a>> {
    let runtime = runtime.context(
        "patch:finding requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = patch_model(raw_input, ctx)?;
    let prompt_override = raw_input
        .get("PATCH_PROMPT")
        .and_then(Value::as_str)
        .map(str::to_string);

    let plan = PatchValidationPlan {
        build: input.build_cmd.clone(),
        test: input.test_cmd.clone(),
    };
    emit_validation_plan_disclosure(ctx, &plan, &input.source_commit);
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .to_string();
    let control = PatchCommandControl::new(ctx.cancellation, input.validation_timeout);
    ensure_git_repository(repo_root, control)?;
    Ok(PatchExecution {
        runtime,
        model,
        prompt_override,
        source_commit: input.source_commit.clone(),
        plan,
        repo_name,
        style: input.style,
        validation_timeout: input.validation_timeout,
    })
}

fn emit_validation_plan_disclosure(
    ctx: &ToolExecutionContext<'_>,
    plan: &PatchValidationPlan,
    source_commit: &str,
) {
    let Some(trace) = ctx.trace else {
        return;
    };
    let _ = trace
        .step(
            "tool-progress",
            "finding",
            validation_plan_disclosure(plan, source_commit),
        )
        .emit();
}

fn resolve_patch_system_prompt(value: Option<&str>, repo_root: &Path) -> Result<String> {
    let default_prompt = patch_system_prompt();
    value
        .map(|value| {
            crate::options::resolve_prepared_prompt_override_for_key(
                value,
                repo_root,
                "PATCH_PROMPT",
                &default_prompt,
            )
        })
        .transpose()
        .map(|prompt| prompt.unwrap_or(default_prompt))
}

fn patch_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "patch:finding",
        input
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        ctx.config.model.as_deref(),
    )
}

struct PatchAttemptOutcome {
    history: Vec<PatchAttempt>,
    final_status: PatchStatus,
    final_diff: Option<String>,
    final_explanation: Option<String>,
    cost: RuntimeCostReport,
}

fn run_patch_attempts(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    repo_root: &Path,
    execution: &PatchExecution<'_>,
    candidate: &ConfirmedPatchFinding,
    input: &PatchFindingInput,
) -> Result<PatchAttemptOutcome> {
    let mut state = PatchAttemptState::default();
    for attempt in 1..=input.max_iterations {
        if run_and_record_patch_attempt(
            ctx,
            parent_step,
            repo_root,
            execution,
            candidate,
            &mut state,
            attempt,
        )? {
            break;
        }
    }
    Ok(state.into_outcome())
}

struct PatchAttemptState {
    history: Vec<PatchAttempt>,
    final_status: PatchStatus,
    final_diff: Option<String>,
    final_explanation: Option<String>,
    cost: RuntimeCostReport,
}

impl Default for PatchAttemptState {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            final_status: PatchStatus::Unknown,
            final_diff: None,
            final_explanation: None,
            cost: RuntimeCostReport::known(RuntimeCost::ZERO),
        }
    }
}

impl PatchAttemptState {
    fn into_outcome(self) -> PatchAttemptOutcome {
        PatchAttemptOutcome {
            history: self.history,
            final_status: self.final_status,
            final_diff: self.final_diff,
            final_explanation: self.final_explanation,
            cost: self.cost,
        }
    }
}

fn run_and_record_patch_attempt(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    repo_root: &Path,
    execution: &PatchExecution<'_>,
    candidate: &ConfirmedPatchFinding,
    state: &mut PatchAttemptState,
    attempt: usize,
) -> Result<bool> {
    let result = run_single_patch_attempt(
        ctx,
        parent_step,
        repo_root,
        execution,
        candidate,
        &state.history,
        attempt,
    )?;
    let sound = result.status == PatchStatus::Sound;
    record_patch_attempt(state, attempt, result)?;
    Ok(sound)
}

fn record_patch_attempt(
    state: &mut PatchAttemptState,
    attempt: usize,
    result: SinglePatchAttempt,
) -> Result<()> {
    let total_cost = accumulate_patch_cost(state.cost, result.cost)?;
    state.history.push(PatchAttempt {
        attempt,
        diff: result.diff.clone(),
        status: result.status,
        output: result.output.clone(),
    });
    state.final_status = result.status;
    state.final_diff = Some(result.diff);
    state.final_explanation = Some(result.explanation);
    state.cost = total_cost;
    Ok(())
}

pub(super) fn accumulate_patch_cost(
    current: RuntimeCostReport,
    attempt: RuntimeCostReport,
) -> Result<RuntimeCostReport> {
    current.checked_add(attempt, "patch synthesis attempt cost")
}

struct SinglePatchAttempt {
    diff: String,
    explanation: String,
    status: PatchStatus,
    output: String,
    cost: RuntimeCostReport,
}

fn run_single_patch_attempt(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    repo_root: &Path,
    execution: &PatchExecution<'_>,
    candidate: &ConfirmedPatchFinding,
    history: &[PatchAttempt],
    attempt: usize,
) -> Result<SinglePatchAttempt> {
    verify_patch_source_snapshot(
        repo_root,
        &execution.source_commit,
        PatchCommandControl::new(ctx.cancellation, execution.validation_timeout),
    )?;
    let synthesis = synthesize_patch_with_scope(
        ctx,
        parent_step,
        repo_root,
        execution,
        candidate,
        history,
        attempt,
    )?;
    emit_patch_guardrail_check(ctx, parent_step, attempt);
    let validation = validate_patch_in_worktree(
        ctx,
        repo_root,
        &synthesis.diff,
        &execution.plan,
        &execution.source_commit,
        execution.validation_timeout,
    )?;
    Ok(SinglePatchAttempt {
        diff: synthesis.diff,
        explanation: synthesis.explanation,
        status: validation.status,
        output: validation.output,
        cost: synthesis.cost,
    })
}

fn synthesize_patch_with_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    repo_root: &Path,
    execution: &PatchExecution<'_>,
    candidate: &ConfirmedPatchFinding,
    history: &[PatchAttempt],
    attempt: usize,
) -> Result<PatchSynthesis> {
    let control = PatchCommandControl::new(ctx.cancellation, execution.validation_timeout);
    with_disposable_worktree(repo_root, &execution.source_commit, control, |worktree| {
        synthesize_patch_in_checkout(
            ctx,
            parent_step,
            worktree,
            execution,
            candidate,
            history,
            attempt,
        )
    })
}

fn synthesize_patch_in_checkout(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    worktree: &Path,
    execution: &PatchExecution<'_>,
    candidate: &ConfirmedPatchFinding,
    history: &[PatchAttempt],
    attempt: usize,
) -> Result<PatchSynthesis> {
    // Phase scope so each attempt's LLM calls (rationale + diff-draft +
    // tests-author) appear under a per-attempt header in the feed.
    let attempt_scope = match (ctx.trace, parent_step) {
        (Some(trace), Some(parent)) => {
            let phase = trace
                .child(parent)
                .step(
                    "reasoning",
                    "finding",
                    format!("rationale · diff-draft (attempt {})", attempt),
                )
                .emit();
            Some((trace.parent_scope(phase), phase))
        }
        _ => None,
    };
    let system_prompt =
        resolve_patch_system_prompt(execution.prompt_override.as_deref(), worktree)?;
    let synthesis = synthesize_patch(
        execution.runtime,
        &execution.model,
        worktree,
        &execution.repo_name,
        &candidate.finding,
        &candidate.triage,
        history,
        execution.style,
        &system_prompt,
    )?;
    drop(attempt_scope);
    Ok(synthesis)
}

fn emit_patch_guardrail_check(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    attempt: usize,
) {
    // Validation phase doesn't make LLM calls but logs a checkpoint.
    if let (Some(trace), Some(parent)) = (ctx.trace, parent_step) {
        let _ = trace
            .child(parent)
            .step(
                "reasoning",
                "finding",
                format!("guardrail-check (attempt {})", attempt),
            )
            .emit();
    }
}

fn validate_patch_in_worktree(
    ctx: &ToolExecutionContext<'_>,
    repo_root: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
    source_commit: &str,
    timeout: std::time::Duration,
) -> Result<ValidationResult> {
    let control = PatchCommandControl::new(ctx.cancellation, timeout);
    with_disposable_worktree(repo_root, source_commit, control, |worktree| {
        validate_patch(worktree, diff, plan, control)
    })
}

fn patch_validator_log(history: &[PatchAttempt]) -> String {
    history
        .iter()
        .map(|attempt| {
            format!(
                "[Attempt {}] {}: {}",
                attempt.attempt,
                attempt.status.as_str(),
                attempt.output
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn patch_result(
    candidate: &ConfirmedPatchFinding,
    execution: &PatchExecution<'_>,
    attempts: PatchAttemptOutcome,
    validator_log: String,
    provenance: PatchProvenance,
) -> PatchResult {
    PatchResult {
        patch_run_id: Uuid::new_v4().to_string(),
        fingerprint: candidate.finding.fingerprint.clone(),
        repo: execution.repo_name.clone(),
        diff: attempts.final_diff,
        status: attempts.final_status,
        iterations: attempts.history.len(),
        build_command: execution.plan.build.clone(),
        test_command: execution.plan.test.clone(),
        worktree_path: None,
        cost_usd: Some(attempts.cost.observed_usd()),
        provider_spend_unresolved: !attempts.cost.is_complete(),
        validator_log: Some(validator_log.clone()),
        history: attempts.history,
        provenance: Some(provenance),
        created_at: None,
        updated_at: None,
    }
}

fn patch_provenance(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
    finding: &Finding,
    source_commit: &str,
) -> Result<PatchProvenance> {
    let detector_binding = direct_detector_binding(target, finding).context(
        "patch:finding requires a canonical detector run and input; re-scan the finding before generating a patch",
    )?;
    let provenance = PatchProvenance {
        source_commit: source_commit.to_string(),
        target: target.display().to_string(),
        originating_run_id: Some(
            ctx.run_id()
                .context("patch:finding requires a canonical patch run id")?,
        ),
        detector_tool: Some(detector_binding.tool),
        detector_run_id: Some(detector_binding.run_id),
        detector_input_digest: Some(detector_binding.input_digest),
    };
    provenance.ensure_complete_for_apply()?;
    Ok(provenance)
}

struct DirectDetectorBinding {
    tool: String,
    run_id: String,
    input_digest: String,
}

fn direct_detector_binding(target: &Path, finding: &Finding) -> Option<DirectDetectorBinding> {
    let run_id = finding.scan_id.as_deref()?;
    let summary = crate::run_artifacts::load_run_summary(target, run_id).ok()?;
    let tool = summary.tool?;
    super::detector_identity::qualified_tool_matches_identity(&tool, &finding.tool).then_some(())?;
    let (_, input) = crate::run_artifacts::read_run_artifact_text(target, run_id, "input.json")
        .require("originating detector input")
        .ok()?;
    Some(DirectDetectorBinding {
        tool,
        run_id: run_id.to_string(),
        input_digest: PatchProvenance::digest_detector_input(input.as_bytes()),
    })
}

fn emit_patch_done(ctx: &ToolExecutionContext<'_>, result: &PatchResult) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "finding",
                format!("patch:finding complete · status={:?}", result.status),
            )
            .emit();
    }
}

#[cfg(test)]
mod detector_provenance_tests {
    use super::*;
    use crate::run_artifacts::{record_tool_run_started, ToolRunRecord};
    use crate::Severity;

    fn context<'a>(config: &'a crate::V2Config) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: None,
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: crate::ExecutionAuthorization::default(),
        }
    }

    #[test]
    fn new_patch_generation_refuses_missing_detector_provenance_before_persistence() {
        let target = tempfile::tempdir().unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "demo.rule",
            "src/lib.rs",
            1,
            None,
            Severity::High,
            "candidate",
        );
        let config = crate::V2Config::default();

        let error = patch_provenance(
            &context(&config),
            target.path(),
            &finding,
            "source-commit",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("canonical detector run"), "{error}");
        assert!(error.contains("re-scan"), "{error}");
    }

    #[test]
    fn module_only_finding_binds_the_canonical_detector_run() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "secret-run";
        record_tool_run_started(
            ToolRunRecord::new(target.path(), run_id, "tool", "secret-scan:scan"),
            &serde_json::json!({"depth": "full"}),
        );
        let mut finding = Finding::new_tool(
            "secret-scan",
            "secret/key",
            "config.env",
            1,
            Some(1),
            Severity::High,
            "exposed key",
        );
        finding.scan_id = Some(run_id.to_string());

        let binding = direct_detector_binding(target.path(), &finding).expect("detector binding");

        assert_eq!(binding.tool, "secret-scan:scan");
        assert_eq!(binding.run_id, run_id);
        assert!(!binding.input_digest.is_empty());
    }

    #[test]
    fn new_patch_generation_requires_its_own_canonical_run_reference() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "secret-run";
        record_tool_run_started(
            ToolRunRecord::new(target.path(), run_id, "tool", "secret-scan:scan"),
            &serde_json::json!({"depth": "full"}),
        );
        let mut finding = Finding::new_tool(
            "secret-scan",
            "secret/key",
            "config.env",
            1,
            Some(1),
            Severity::High,
            "exposed key",
        );
        finding.scan_id = Some(run_id.to_string());
        let config = crate::V2Config::default();

        let error = patch_provenance(
            &context(&config),
            target.path(),
            &finding,
            "source-commit",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("canonical patch run id"), "{error}");
    }
}
