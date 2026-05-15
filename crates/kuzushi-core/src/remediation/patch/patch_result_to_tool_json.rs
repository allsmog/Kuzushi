use super::*;

pub(crate) fn patch_result_to_tool_json(
    fingerprint: &str,
    result: &PatchResult,
    validator_log: &str,
    explanation: Option<&str>,
) -> Value {
    let summary = format!("patch:finding {}", result.status.as_str());
    let report_markdown = patch_report_markdown(fingerprint, result, explanation);
    let proof = patch_proof_snapshot(fingerprint, result);

    json!({
        "ok": patch_output_ok(result.status),
        "status": patch_output_status(result.status),
        "summary": summary,
        "output": patch_output_lines(fingerprint, result, validator_log).join("\n"),
        "reportMarkdown": report_markdown,
        "artifacts": [],
        "warnings": patch_warnings(result.status, validator_log),
        "errors": patch_errors(result.status, validator_log),
        "data": patch_output_data(result, explanation, &summary, &proof, &report_markdown),
        "proof": proof,
        "costUsd": 0.0,
    })
}

fn patch_output_lines(fingerprint: &str, result: &PatchResult, validator_log: &str) -> Vec<String> {
    let mut lines = patch_header_lines(fingerprint, result);
    append_patch_details(&mut lines, result, validator_log);
    lines
}

fn patch_header_lines(fingerprint: &str, result: &PatchResult) -> Vec<String> {
    vec![
        format!(
            "[{}] patch:finding {}",
            if patch_is_sound(result.status) { "+" } else { "!" },
            result.status.as_str()
        ),
        format!("      fingerprint:   {fingerprint}"),
        format!("      iterations:    {}", result.iterations),
        "      cost:          $0.0000".to_string(),
    ]
}

fn append_patch_details(lines: &mut Vec<String>, result: &PatchResult, validator_log: &str) {
    if patch_is_sound(result.status) {
        append_patch_diff(lines, result);
    } else if !validator_log.trim().is_empty() {
        lines.push(String::new());
        lines.push("Validator log:".to_string());
        lines.push(validator_log.to_string());
    }
}

fn append_patch_diff(lines: &mut Vec<String>, result: &PatchResult) {
    if let Some(diff) = result.diff.as_ref().filter(|value| !value.trim().is_empty()) {
        lines.push(String::new());
        lines.push("Diff:".to_string());
        lines.push(diff.to_string());
    }
}

fn patch_output_data(
    result: &PatchResult,
    explanation: Option<&str>,
    summary: &str,
    proof: &Value,
    report_markdown: &str,
) -> Value {
    json!({
        "summary": summary,
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
        "proof": proof,
        "reportMarkdown": report_markdown,
    })
}

fn patch_output_status(status: PatchStatus) -> &'static str {
    if patch_is_sound(status) {
        "completed"
    } else {
        "partial"
    }
}

fn patch_output_ok(status: PatchStatus) -> bool {
    status != PatchStatus::Unknown
}

fn patch_is_sound(status: PatchStatus) -> bool {
    matches!(status, PatchStatus::Sound | PatchStatus::Verified)
}

fn patch_warnings(status: PatchStatus, validator_log: &str) -> Vec<String> {
    if patch_is_sound(status) {
        Vec::new()
    } else {
        vec![patch_validator_message(status, validator_log)]
    }
}

fn patch_errors(status: PatchStatus, validator_log: &str) -> Vec<String> {
    if status == PatchStatus::Unknown {
        vec![patch_validator_message(status, validator_log)]
    } else {
        Vec::new()
    }
}

fn patch_validator_message(status: PatchStatus, validator_log: &str) -> String {
    if validator_log.trim().is_empty() {
        return format!("Patch finished with status {}.", status.as_str());
    }
    format!("Patch finished with status {}. See validator log.", status.as_str())
}

fn patch_report_markdown(
    fingerprint: &str,
    result: &PatchResult,
    explanation: Option<&str>,
) -> String {
    [
        format!("# Patch Report - {fingerprint}"),
        String::new(),
        format!("- Status: {}", result.status.as_str()),
        format!("- Iterations: {}", result.iterations),
        format!("- Patch run: {}", result.patch_run_id),
        format!(
            "- Explanation: {}",
            explanation.unwrap_or("No explanation was recorded.")
        ),
    ]
    .join("\n")
}

fn patch_proof_snapshot(fingerprint: &str, result: &PatchResult) -> Value {
    json!({
        "kind": "patch-validation",
        "fingerprint": fingerprint,
        "patchRunId": result.patch_run_id,
        "patchStatus": result.status.as_str(),
        "iterations": result.iterations,
        "buildCommand": result.build_command,
        "testCommand": result.test_command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_result_exposes_report_and_proof_snapshots() {
        let result = PatchResult {
            patch_run_id: "patch-1".to_string(),
            fingerprint: "fp-1".to_string(),
            repo: "repo".to_string(),
            diff: Some("diff --git a/x b/x".to_string()),
            status: PatchStatus::Sound,
            iterations: 1,
            build_command: Some("cargo build".to_string()),
            test_command: Some("cargo test".to_string()),
            worktree_path: None,
            cost_usd: Some(0.0),
            validator_log: Some("ok".to_string()),
            history: Vec::new(),
            created_at: None,
            updated_at: None,
        };

        let output = patch_result_to_tool_json("fp-1", &result, "ok", Some("fixed bounds"));

        assert_eq!(output["status"], json!("completed"));
        assert_eq!(output["proof"]["patchStatus"], json!("SOUND"));
        assert!(output["reportMarkdown"].as_str().unwrap().contains("Patch Report"));
    }
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
