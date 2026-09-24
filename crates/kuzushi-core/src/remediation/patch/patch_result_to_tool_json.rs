use super::*;

pub(crate) fn patch_result_to_tool_json(
    fingerprint: &str,
    result: &PatchResult,
    validator_log: &str,
    explanation: Option<&str>,
) -> Result<Value> {
    let cost = patch_runtime_cost_report(result)?;
    let summary = format!("patch:finding {}", result.status.as_str());
    let report_markdown = patch_report_markdown(fingerprint, result, explanation, cost);
    let proof = patch_proof_snapshot(fingerprint, result);

    let mut output = json!({
        "ok": patch_output_ok(result.status),
        "status": patch_output_status(result.status),
        "summary": summary,
        "output": patch_output_lines(fingerprint, result, validator_log, cost).join("\n"),
        "reportMarkdown": report_markdown,
        "artifacts": [],
        "warnings": patch_warnings(result.status, validator_log),
        "errors": patch_errors(result.status, validator_log),
        "data": patch_output_data(result, explanation, &summary, &proof, &report_markdown),
        "proof": proof,
    });
    crate::module_result::apply_runtime_cost_report(&mut output, cost);
    Ok(output)
}

fn patch_runtime_cost_report(result: &PatchResult) -> Result<RuntimeCostReport> {
    let Some(cost_usd) = result.validated_cost_usd()? else {
        return Ok(RuntimeCostReport::UNAVAILABLE);
    };
    let cost = RuntimeCost::from_usd(cost_usd, "patch result cost")?;
    Ok(if result.provider_spend_unresolved {
        RuntimeCostReport::incomplete(cost)
    } else {
        RuntimeCostReport::known(cost)
    })
}

fn patch_output_lines(
    fingerprint: &str,
    result: &PatchResult,
    validator_log: &str,
    cost: RuntimeCostReport,
) -> Vec<String> {
    let mut lines = patch_header_lines(fingerprint, result, cost);
    append_patch_details(&mut lines, result, validator_log);
    lines
}

fn patch_header_lines(
    fingerprint: &str,
    result: &PatchResult,
    cost: RuntimeCostReport,
) -> Vec<String> {
    vec![
        format!(
            "[{}] patch:finding {}",
            if patch_is_sound(result.status) {
                "+"
            } else {
                "!"
            },
            result.status.as_str()
        ),
        format!("      fingerprint:   {fingerprint}"),
        format!("      iterations:    {}", result.iterations),
        patch_cost_line(cost),
    ]
}

fn patch_cost_line(cost: RuntimeCostReport) -> String {
    format!("      cost:          {}", patch_cost_label(cost))
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
    if let Some(diff) = result
        .diff
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
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
        "patchResult": result,
        "summary": summary,
        "status": result.status.as_str(),
        "iterations": result.iterations,
        "patchRunId": result.patch_run_id,
        "diff": result.diff,
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
    format!(
        "Patch finished with status {}. See validator log.",
        status.as_str()
    )
}

fn patch_report_markdown(
    fingerprint: &str,
    result: &PatchResult,
    explanation: Option<&str>,
    cost: RuntimeCostReport,
) -> String {
    [
        format!("# Patch Report - {fingerprint}"),
        String::new(),
        format!("- Status: {}", result.status.as_str()),
        format!("- Iterations: {}", result.iterations),
        format!("- Patch run: {}", result.patch_run_id),
        format!("- Cost: {}", patch_cost_label(cost)),
        format!(
            "- Explanation: {}",
            explanation.unwrap_or("No explanation was recorded.")
        ),
    ]
    .join("\n")
}

fn patch_cost_label(cost: RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return "unavailable".to_string();
    }
    match cost.exact_usd() {
        Some(exact) => format!("${exact:.4}"),
        None => format!(
            "observed ${:.4}; provider spend unresolved",
            cost.observed_usd()
        ),
    }
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
        let mut result = patch_result();
        result.diff = Some("diff --git a/x b/x".to_string());
        result.build_command = Some("cargo build".to_string());
        result.test_command = Some("cargo test".to_string());
        result.validator_log = Some("ok".to_string());
        result.provenance = Some(patch_provenance());

        let output =
            patch_result_to_tool_json("fp-1", &result, "ok", Some("fixed bounds")).unwrap();

        assert_eq!(output["status"], json!("completed"));
        assert_eq!(output["costUsd"], json!(0.0));
        assert_eq!(output["data"]["costUsd"], json!(0.0));
        assert!(output["output"]
            .as_str()
            .unwrap()
            .contains("cost:          $0.0000"));
        assert_eq!(output["proof"]["patchStatus"], json!("SOUND"));
        assert_eq!(
            output["data"]["patchResult"]["provenance"]["sourceCommit"],
            json!("0123456789012345678901234567890123456789")
        );
        assert!(output["reportMarkdown"]
            .as_str()
            .unwrap()
            .contains("Patch Report"));
    }

    #[test]
    fn incomplete_patch_cost_exposes_observed_spend_without_exact_cost() {
        let mut result = patch_result();
        result.cost_usd = Some(0.25);
        result.provider_spend_unresolved = true;

        let output = patch_result_to_tool_json("fp-1", &result, "ok", None).unwrap();

        assert!(output.get("costUsd").is_none());
        assert!(output["data"].get("costUsd").is_none());
        assert_eq!(output["observedCostUsd"], json!(0.25));
        assert_eq!(output["data"]["observedCostUsd"], json!(0.25));
        assert_eq!(output["providerSpendUnresolved"], json!(true));
        assert!(output["output"]
            .as_str()
            .unwrap()
            .contains("observed $0.2500; provider spend unresolved"));
    }

    #[test]
    fn unavailable_patch_cost_omits_monetary_fields_and_says_unavailable() {
        let mut result = patch_result();
        result.cost_usd = None;

        let output = patch_result_to_tool_json("fp-1", &result, "ok", None).unwrap();

        for value in [&output, &output["data"]] {
            assert!(value.get("costUsd").is_none());
            assert!(value.get("observedCostUsd").is_none());
            assert!(value.get("providerSpendUnresolved").is_none());
        }
        assert!(output["output"]
            .as_str()
            .unwrap()
            .contains("cost:          unavailable"));
        assert!(output["reportMarkdown"]
            .as_str()
            .unwrap()
            .contains("Cost: unavailable"));
    }

    fn patch_result() -> PatchResult {
        PatchResult {
            patch_run_id: "patch-1".to_string(),
            fingerprint: "fp-1".to_string(),
            repo: "repo".to_string(),
            diff: None,
            status: PatchStatus::Sound,
            iterations: 1,
            build_command: None,
            test_command: None,
            worktree_path: None,
            cost_usd: Some(0.0),
            provider_spend_unresolved: false,
            validator_log: None,
            history: Vec::new(),
            provenance: None,
            created_at: None,
            updated_at: None,
        }
    }

    fn patch_provenance() -> PatchProvenance {
        PatchProvenance {
            source_commit: "0123456789012345678901234567890123456789".to_string(),
            target: "/repo".to_string(),
            originating_run_id: Some("run-patch".to_string()),
            detector_tool: Some("semgrep:scan".to_string()),
            detector_run_id: Some("run-scan".to_string()),
            detector_input_digest: Some("digest".to_string()),
            reproducer: None,
            verification_source_identity: None,
            verification_run_id: None,
        }
    }
}

pub(crate) fn synthesize_patch(
    runtime: &dyn AgentRuntime,
    model: &str,
    repo_root: &Path,
    repo_name: &str,
    finding: &Finding,
    confirmation: &ReviewConfirmation,
    history: &[PatchAttempt],
    style: PatchStyle,
    system_prompt: &str,
) -> Result<PatchSynthesis> {
    let prompt = build_patch_prompt(repo_root, repo_name, finding, confirmation, history, style)?;
    let costed = query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            model.to_string(),
            repo_root.to_path_buf(),
            system_prompt.to_string(),
            prompt,
        ),
        StructuredJsonContract::new("patch:finding", "PatchSynthesis", patch_synthesis_schema()),
        parse_patch_synthesis,
    )?;
    let cost = costed.cost_report()?;
    Ok(PatchSynthesis {
        diff: costed.value.diff,
        explanation: costed.value.explanation,
        cost,
    })
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
