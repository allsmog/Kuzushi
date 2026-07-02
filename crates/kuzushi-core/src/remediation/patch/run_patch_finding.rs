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
    emit_patch_progress(ctx, parent_step, "execution · detect validation plan");
    let execution = patch_execution(ctx, runtime, resources.workspace.root(), &input, &raw_input)?;
    let attempts = run_patch_attempts(
        ctx,
        parent_step,
        resources.workspace.root(),
        &execution,
        &candidate,
        &input,
    )?;
    let validator_log = patch_validator_log(&attempts.history);
    let final_explanation = attempts.final_explanation.clone();
    let result = patch_result(&candidate, &execution, attempts, validator_log.clone());
    emit_patch_progress(ctx, parent_step, "persist · save patch result");
    resources.store.insert_patch_result(&result)?;
    emit_patch_done(ctx, &result);
    Ok(patch_result_to_tool_json(
        &candidate.finding.fingerprint,
        &result,
        &validator_log,
        final_explanation.as_deref(),
    ))
}

struct PatchResources<'a> {
    workspace: &'a crate::workspace::WorkspaceTarget,
    store: &'a crate::findings::FindingStore,
}

fn patch_resources<'a>(ctx: &'a ToolExecutionContext<'a>) -> Result<PatchResources<'a>> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message("patch:finding"))?;
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
    plan: PatchValidationPlan,
    repo_name: String,
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

    let detected = detect_validation_plan(repo_root);
    let plan = PatchValidationPlan {
        build: input.build_cmd.clone().or(detected.build),
        test: input.test_cmd.clone().or(detected.test),
    };
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .to_string();
    ensure_git_repository(repo_root)?;
    Ok(PatchExecution {
        runtime,
        model,
        plan,
        repo_name,
    })
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
}

impl Default for PatchAttemptState {
    fn default() -> Self {
        Self {
            history: Vec::new(),
            final_status: PatchStatus::Unknown,
            final_diff: None,
            final_explanation: None,
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
    record_patch_attempt(state, attempt, result);
    Ok(sound)
}

fn record_patch_attempt(state: &mut PatchAttemptState, attempt: usize, result: SinglePatchAttempt) {
    state.history.push(PatchAttempt {
        attempt,
        diff: result.diff.clone(),
        status: result.status,
        output: result.output.clone(),
    });
    state.final_status = result.status;
    state.final_diff = Some(result.diff);
    state.final_explanation = Some(result.explanation);
}

struct SinglePatchAttempt {
    diff: String,
    explanation: String,
    status: PatchStatus,
    output: String,
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
    let validation = validate_patch_in_worktree(repo_root, &synthesis.diff, &execution.plan)?;
    Ok(SinglePatchAttempt {
        diff: synthesis.diff,
        explanation: synthesis.explanation,
        status: validation.status,
        output: validation.output,
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
    let synthesis = synthesize_patch(
        execution.runtime,
        &execution.model,
        repo_root,
        &execution.repo_name,
        &candidate.finding,
        &candidate.triage,
        history,
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
    repo_root: &Path,
    diff: &str,
    plan: &PatchValidationPlan,
) -> Result<ValidationResult> {
    let worktree = create_disposable_worktree(repo_root)?;
    let validation = validate_patch(&worktree, diff, plan);
    cleanup_worktree(repo_root, &worktree);
    Ok(validation)
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
        cost_usd: Some(0.0),
        validator_log: Some(validator_log.clone()),
        history: attempts.history,
        created_at: None,
        updated_at: None,
    }
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
