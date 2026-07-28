use super::*;

pub(crate) fn query_agentic_sast_findings_with_cost(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    review_context: Option<&str>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    query_required_structured_json_with_cost(
        runtime,
        agentic_sast_query_request(run, review_context),
        StructuredJsonContract::from_schema::<crate::structured_output::FindingsOutput>(
            "agentic-sast:scan",
            "AgenticSastFindings",
        ),
        |raw| normalize_and_filter_agentic_sast_findings(raw, run),
    )
}

fn agentic_sast_query_request(
    run: &AgenticSastRun,
    review_context: Option<&str>,
) -> AgentQueryRequest {
    let stage = if review_context.is_some() {
        "agentic-sast:review"
    } else {
        "agentic-sast:hunt"
    };
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
            &run.enrichment,
        ),
    )
    .with_stage(stage)
    .with_tool_policy(run.tool_policy.clone())
}

fn normalize_and_filter_agentic_sast_findings(
    raw: Value,
    run: &AgenticSastRun,
) -> Result<Vec<Finding>> {
    let mut findings = normalize_agentic_sast_findings(
        require_json_object(raw)?,
        &run.target,
        run.options.max_findings,
        run.whitebox_static,
    )?;
    findings.retain(|finding| {
        agentic_path_allowed(
            &finding.file_path,
            &run.options.include_patterns,
            &run.options.exclude_patterns,
        )
    });
    Ok(findings)
}

pub(crate) fn merge_agentic_sast_findings(
    first_pass: Vec<Finding>,
    review_pass: Vec<Finding>,
    max_findings: usize,
) -> Vec<Finding> {
    let mut key_to_index = BTreeMap::new();
    let mut merged = Vec::new();
    for finding in first_pass.into_iter().chain(review_pass) {
        let key = agentic_finding_merge_key(&finding);
        if let Some(index) = key_to_index.get(&key).copied() {
            if should_replace_agentic_finding(&merged[index], &finding) {
                merged[index] = finding;
            }
        } else {
            key_to_index.insert(key, merged.len());
            merged.push(finding);
        }
    }
    merged.truncate(max_findings);
    merged
}

fn agentic_finding_merge_key(finding: &Finding) -> (String, String, String, u32, u32) {
    (
        normalize_agentic_merge_key_part(&finding.tool),
        normalize_agentic_merge_key_part(&finding.rule_id),
        normalize_agentic_merge_path(&finding.file_path),
        finding.start_line,
        finding.end_line.unwrap_or(finding.start_line),
    )
}

fn normalize_agentic_merge_key_part(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_agentic_merge_path(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("./")
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn should_replace_agentic_finding(existing: &Finding, candidate: &Finding) -> bool {
    let existing_rank = agentic_merge_severity_rank(existing.severity);
    let candidate_rank = agentic_merge_severity_rank(candidate.severity);
    candidate_rank > existing_rank
        || (candidate_rank == existing_rank
            && agentic_finding_evidence_weight(candidate)
                > agentic_finding_evidence_weight(existing))
}

fn agentic_merge_severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

fn agentic_finding_evidence_weight(finding: &Finding) -> usize {
    finding.title.trim().len() + finding.message.trim().len()
}

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("structured output parse failed: expected a JSON object")
    }
}
