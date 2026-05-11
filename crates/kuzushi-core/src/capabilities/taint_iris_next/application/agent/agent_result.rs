use super::*;

pub(in crate::capabilities::taint_iris_next) fn normalized_taint_iris_next_agent_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    raw: Value,
    retry_count: usize,
    cost_usd: f64,
) -> Result<TaintIrisNextAgentResult> {
    let Value::Object(object) = raw.clone() else {
        anyhow::bail!("taint-iris-next:hunt expected agent output to be a JSON object");
    };
    let selections = normalize_taint_iris_next_selections(
        read_object_value(&object, &["selectedCwes", "selected_cwes"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        &plan.catalog,
    )?;
    let (mut findings, mut warnings) = normalize_taint_iris_next_findings(
        read_object_value(&object, &["findings"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        plan,
        evidence,
    )?;
    let triage = normalize_taint_iris_next_triage(
        read_object_value(&object, &["triage"])
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    let mut outcome = evidence.outcome.clone();
    let agent_status = if selections.is_empty() {
        "no-selection".to_string()
    } else {
        "valid-json".to_string()
    };
    if let Some(result) = no_selection_taint_iris_next_result(
        plan,
        evidence,
        &selections,
        &findings,
        &mut warnings,
        &raw,
        retry_count,
        cost_usd,
    ) {
        return Ok(result);
    }
    if selections.is_empty() && !evidence.evidence.is_empty() {
        warnings.push(format!(
            "agent selected no CWEs from {} evidence row(s)",
            evidence.evidence.len()
        ));
        outcome = "agent-no-selection".to_string();
    }
    findings.truncate(plan.caps.max_agent_findings);
    Ok(TaintIrisNextAgentResult {
        agent_status,
        selected_cwes: selections,
        findings,
        review_candidates: Vec::new(),
        triage_summary: summarize_taint_iris_next_triage(&triage),
        triage,
        outcome,
        raw_output: raw,
        structured_output_valid: true,
        structured_output_retry_count: retry_count,
        parse_error: None,
        result_text_excerpt: None,
        warnings,
        cost_usd,
    })
}

pub(in crate::capabilities::taint_iris_next) fn no_selection_taint_iris_next_result(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    selections: &[Value],
    findings: &[Finding],
    warnings: &mut Vec<String>,
    raw: &Value,
    retry_count: usize,
    cost_usd: f64,
) -> Option<TaintIrisNextAgentResult> {
    if !selections.is_empty() || !findings.is_empty() || evidence.linked_stories.is_empty() {
        return None;
    }
    let (fallback_findings, fallback_selections, fallback_triage) =
        deterministic_taint_iris_next_fallback(plan, evidence);
    if fallback_findings.is_empty() {
        return None;
    }
    warnings.push(format!(
        "agent selected no CWEs; returning {} deterministic linked finding candidate(s) for review",
        fallback_findings.len()
    ));
    Some(TaintIrisNextAgentResult {
        agent_status: "no-selection-fallback".to_string(),
        selected_cwes: fallback_selections,
        findings: fallback_findings.clone(),
        review_candidates: fallback_findings,
        triage: fallback_triage.clone(),
        triage_summary: summarize_taint_iris_next_triage(&fallback_triage),
        outcome: "agent-no-selection".to_string(),
        raw_output: raw.clone(),
        structured_output_valid: true,
        structured_output_retry_count: retry_count,
        parse_error: None,
        result_text_excerpt: None,
        warnings: warnings.clone(),
        cost_usd,
    })
}
