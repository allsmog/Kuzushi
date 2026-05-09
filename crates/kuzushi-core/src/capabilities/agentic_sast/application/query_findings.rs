use super::*;

pub(crate) fn query_agentic_sast_findings(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    review_context: Option<&str>,
) -> Result<Vec<Finding>> {
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            run.model.clone(),
            run.target.clone(),
            run.system_prompt.clone(),
            build_agentic_sast_prompt(
                &run.target,
                &run.options,
                &run.inventory,
                review_context,
                run.whitebox_static,
            ),
        )
        .with_tool_policy(run.tool_policy.clone()),
        StructuredJsonContract::new(
            "agentic-sast:scan",
            "AgenticSastFindings",
            findings_array_schema(),
        ),
        require_json_object,
    )?;
    normalize_agentic_sast_findings(
        raw,
        &run.target,
        run.options.max_findings,
        run.whitebox_static,
    )
}

pub(crate) fn maybe_review_agentic_sast_findings(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    findings: Vec<Finding>,
) -> Result<Vec<Finding>> {
    if run.options.passes != 2 || findings.is_empty() {
        return Ok(findings);
    }
    let review_context = summarize_agentic_findings_for_review(&findings);
    let review_findings = query_agentic_sast_findings(runtime, run, Some(&review_context))?;
    Ok(merge_agentic_sast_findings(
        findings,
        review_findings,
        run.options.max_findings,
    ))
}

pub(crate) fn merge_agentic_sast_findings(
    first_pass: Vec<Finding>,
    review_pass: Vec<Finding>,
    max_findings: usize,
) -> Vec<Finding> {
    let mut merged = BTreeMap::new();
    for finding in first_pass.into_iter().chain(review_pass) {
        merged.entry(finding.fingerprint.clone()).or_insert(finding);
    }
    merged.into_values().take(max_findings).collect()
}

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("structured output parse failed: expected a JSON object")
    }
}

pub(crate) fn findings_array_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}
