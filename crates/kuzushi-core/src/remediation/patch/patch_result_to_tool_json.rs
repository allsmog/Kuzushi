use super::*;

pub(crate) fn patch_result_to_tool_json(
    fingerprint: &str,
    result: &PatchResult,
    validator_log: &str,
    explanation: Option<&str>,
) -> Value {
    let sound = result.status == PatchStatus::Sound;
    let mut lines = vec![
        format!(
            "[{}] patch:finding {}",
            if sound { "+" } else { "!" },
            result.status.as_str()
        ),
        format!("      fingerprint:   {fingerprint}"),
        format!("      iterations:    {}", result.iterations),
        "      cost:          $0.0000".to_string(),
    ];

    if sound {
        if let Some(diff) = result
            .diff
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            lines.push(String::new());
            lines.push("Diff:".to_string());
            lines.push(diff.to_string());
        }
    } else if !validator_log.trim().is_empty() {
        lines.push(String::new());
        lines.push("Validator log:".to_string());
        lines.push(validator_log.to_string());
    }

    json!({
        "ok": sound,
        "output": lines.join("\n"),
        "data": {
            "status": result.status.as_str(),
            "iterations": result.iterations,
            "patchRunId": result.patch_run_id,
            "diff": result.diff,
            "costUsd": 0.0,
            "validatorLog": result.validator_log,
            "history": result.history,
            "buildCommand": result.build_command,
            "testCommand": result.test_command,
            "worktreePath": result.worktree_path,
            "explanation": explanation,
        },
        "costUsd": 0.0,
    })
}

pub(crate) fn synthesize_patch(
    runtime: &dyn AgentRuntime,
    model: &str,
    repo_root: &Path,
    repo_name: &str,
    finding: &Finding,
    triage: &TriageOutcome,
    history: &[PatchAttempt],
) -> Result<PatchSynthesis> {
    let prompt = build_patch_prompt(repo_root, repo_name, finding, triage, history)?;
    query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            repo_root.to_path_buf(),
            PATCH_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new("patch:finding", "PatchSynthesis", patch_synthesis_schema()),
        parse_patch_synthesis,
    )
}

pub(crate) fn patch_synthesis_schema() -> Value {
    json!({
        "type": "object",
        "required": ["diff", "explanation"],
        "additionalProperties": false,
        "properties": {
            "diff": {"type": "string"},
            "explanation": {"type": "string"}
        }
    })
}
