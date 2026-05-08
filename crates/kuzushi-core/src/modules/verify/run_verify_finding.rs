use super::*;

pub(in crate::modules) fn run_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:finding requires a findings store for the active workspace")?;
    let input = VerifyFindingInput::from_tool_input(&input, workspace.root())?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "finding",
                format!("verify start · fp={}", input.fingerprint),
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
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "reasoning",
                "finding",
                format!(
                    "evidence-pull · severity={:?} verdict={:?}",
                    finding.severity, triage.verdict,
                ),
            )
            .emit();
    }
    let runtime = runtime.context(
        "verify:finding requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let model = ctx.config.model.clone().context(
        "verify:finding requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;

    let prompt = build_verify_prompt(&finding, &triage, input.prompt_template.as_deref())?;
    let result = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            workspace.root().to_path_buf(),
            VERIFY_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new(
            "verify:finding",
            "VerificationResult",
            verification_result_schema(),
        ),
        |raw| normalize_verification_result(raw, &finding.fingerprint),
    )?;
    let exploitable = result
        .get("exploitable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let verdict = if exploitable {
        "VULNERABLE"
    } else {
        "not-exploitable"
    };
    if let Some(trace) = ctx.trace {
        let mut step =
            trace.step("done", "finding", format!("verify · {verdict}"));
        if exploitable {
            step = step.with_severity("warn");
        }
        let _ = step.emit();
    }
    let mut lines = vec![
        "[+] verify:finding complete".to_string(),
        format!("      {verdict}"),
    ];
    if let Some(vector) = result
        .get("attackVector")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        lines.push(format!("      vector: {vector}"));
    }
    lines.push("      cost=$0.0000".to_string());

    Ok(json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": result,
        "costUsd": 0.0,
    }))
}

pub(in crate::modules) fn run_verify_exploit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:exploit needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:exploit requires a findings store for the active workspace")?;

    let input = VerifyExploitInput::from_tool_input(&input)?;
    let Some(finding) = store.get_finding_by_reference(&input.fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!("[-] No finding with fingerprint '{}'.", input.fingerprint),
        }));
    };

    let outcome = run_empirical_verify(&finding, &input)?;
    let persisted_id = persist_verify_exploit_outcome(store, &finding, &outcome);
    let response = verify_exploit_response(&finding, &outcome, persisted_id);
    let _ = workspace;
    Ok(response)
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct VerifyExploitInput {
    pub(in crate::modules) fingerprint: String,
    pub(in crate::modules) trust_plain_backend: bool,
    pub(in crate::modules) timeout_ms: u64,
}
