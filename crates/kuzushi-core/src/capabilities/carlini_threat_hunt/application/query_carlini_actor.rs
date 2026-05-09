use super::*;

pub(crate) fn query_carlini_actor(
    runtime: &dyn AgentRuntime,
    input: &Value,
    target: &Path,
    options: &CarliniInput,
    model: &str,
    inventory: &[(String, String)],
    actor_hunt: &ActorHunt,
    actor_fingerprint: &str,
) -> Result<Value> {
    let prompt = build_actor_prompt(target, actor_hunt, options, inventory, actor_fingerprint);
    let request = carlini_actor_request(model, target, prompt, input);
    query_required_structured_json(
        runtime,
        request,
        StructuredJsonContract::new(
            "carlini-threat-hunt:run",
            "CarliniThreatFindings",
            findings_schema(),
        ),
        require_json_object,
    )
}

fn carlini_actor_request(
    model: &str,
    target: &Path,
    prompt: String,
    input: &Value,
) -> AgentQueryRequest {
    AgentQueryRequest::new(
        model.to_string(),
        target.to_path_buf(),
        SYSTEM_PROMPT.to_string(),
        prompt,
    )
    .with_tool_policy(default_whitebox_static_agent_tool_policy())
    .with_thinking_level(carlini_thinking_level(input))
}

pub(in crate::capabilities::carlini_threat_hunt) fn carlini_thinking_level(
    input: &Value,
) -> String {
    carlini_thinking_level_override(input).unwrap_or_else(|| "high".to_string())
}

fn carlini_thinking_level_override(input: &Value) -> Option<String> {
    ["thinkingLevel", "reasoningEffort", "effort"]
        .iter()
        .find_map(|key| nonempty_input_string(input, key))
}

fn nonempty_input_string(input: &Value, key: &str) -> Option<String> {
    let value = input.get(key)?.as_str()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub(crate) fn record_unique_carlini_findings(
    state: &mut CarliniActorRunState,
    findings: Vec<Finding>,
) {
    for finding in findings {
        let dedupe_key = carlini_dedupe_key(&finding);
        if state.seen.insert(dedupe_key) {
            state.findings.push(finding);
        }
    }
}

pub(crate) fn carlini_dedupe_key(finding: &Finding) -> String {
    format!(
        "{}|{}|{}",
        finding.rule_id, finding.file_path, finding.start_line
    )
}

pub(crate) fn finalize_carlini_findings(
    input: &Value,
    findings: &mut Vec<Finding>,
    max_findings: usize,
) -> Result<()> {
    findings.truncate(max_findings);
    apply_carlini_static_profile(input, findings)
}

pub(crate) fn apply_carlini_static_profile(
    input: &Value,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    if whitebox_static_profile_requested(input)? {
        mark_whitebox_static_findings(findings, StaticProofState::CodeCited)?;
    }
    Ok(())
}

pub(crate) fn carlini_threat_hunt_report(
    target: PathBuf,
    ctx: &ToolExecutionContext<'_>,
    options: CarliniInput,
    actors: usize,
    actor_runs: usize,
    findings: Vec<Finding>,
) -> Result<CarliniThreatHuntReport> {
    let persisted = persist_findings(&target, &findings, ctx)?;
    Ok(CarliniThreatHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        actors,
        actor_runs,
        findings,
        persisted,
        kb_context: Some(options.kb_context),
        cost_usd: 0.0,
    })
}
