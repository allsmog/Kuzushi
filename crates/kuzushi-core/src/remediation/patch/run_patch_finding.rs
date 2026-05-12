use super::*;

pub fn run_patch_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "patch:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("patch:finding requires a findings store for the active workspace")?;
    let input = PatchFindingInput::from_tool_input(&input)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "finding",
                format!("patch:finding start · fp={}", input.fingerprint),
            )
            .emit();
    }
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };
    let Some(triage) = finding.triage.clone() else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' has no triage verdict. Run triage:run first.",
                finding.fingerprint
            ),
        }));
    };
    if triage.verdict != TriageVerdict::TruePositive {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "[-] Finding '{}' is not confirmed true_positive; patch:finding only patches confirmed findings.",
                finding.fingerprint
            ),
        }));
    }

    let runtime = runtime.context(
        "patch:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model =
        crate::runtime::require_configured_model("patch:finding", ctx.config.model.as_deref())?;

    let detected = detect_validation_plan(workspace.root());
    let plan = PatchValidationPlan {
        build: input.build_cmd.or(detected.build),
        test: input.test_cmd.or(detected.test),
    };
    let repo_name = workspace
        .root()
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo")
        .to_string();
    ensure_git_repository(workspace.root())?;

    let patch_run_id = Uuid::new_v4().to_string();
    let mut history = Vec::new();
    let mut final_status = PatchStatus::Unknown;
    let mut final_diff = None;
    let mut final_explanation = None;

    for attempt in 1..=input.max_iterations {
        // Phase scope so each attempt's LLM calls (rationale + diff-draft +
        // tests-author) appear under a per-attempt header in the feed.
        let attempt_scope = ctx.trace.map(|trace| {
            let phase = trace
                .step(
                    "reasoning",
                    "finding",
                    format!("rationale · diff-draft (attempt {})", attempt),
                )
                .emit();
            (trace.parent_scope(phase), phase)
        });
        let synthesis = synthesize_patch(
            runtime,
            &model,
            workspace.root(),
            &repo_name,
            &finding,
            &triage,
            &history,
        )?;
        drop(attempt_scope);
        // Validation phase doesn't make LLM calls but logs a checkpoint.
        if let Some(trace) = ctx.trace {
            let _ = trace
                .step(
                    "reasoning",
                    "finding",
                    format!("guardrail-check (attempt {})", attempt),
                )
                .emit();
        }
        let worktree = create_disposable_worktree(workspace.root())?;
        let validation = validate_patch(&worktree, &synthesis.diff, &plan);
        cleanup_worktree(workspace.root(), &worktree);

        history.push(PatchAttempt {
            attempt,
            diff: synthesis.diff.clone(),
            status: validation.status,
            output: validation.output.clone(),
        });
        final_status = validation.status;
        final_diff = Some(synthesis.diff);
        final_explanation = Some(synthesis.explanation);
        if validation.status == PatchStatus::Sound {
            break;
        }
    }

    let validator_log = history
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
        .join("\n\n");

    let result = PatchResult {
        patch_run_id,
        fingerprint: finding.fingerprint.clone(),
        repo: repo_name,
        diff: final_diff,
        status: final_status,
        iterations: history.len(),
        build_command: plan.build.clone(),
        test_command: plan.test.clone(),
        worktree_path: None,
        cost_usd: Some(0.0),
        validator_log: Some(validator_log.clone()),
        history,
        created_at: None,
        updated_at: None,
    };
    store.insert_patch_result(&result)?;

    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "finding",
                format!("patch:finding complete · status={:?}", result.status),
            )
            .emit();
    }
    Ok(patch_result_to_tool_json(
        &finding.fingerprint,
        &result,
        &validator_log,
        final_explanation.as_deref(),
    ))
}
