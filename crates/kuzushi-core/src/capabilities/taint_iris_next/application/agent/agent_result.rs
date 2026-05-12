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
    // Deliberately *do not* substitute deterministic fallback findings here.
    // The agent returned valid JSON — if it chose to emit no CWEs we treat
    // that as a considered rejection of the linked-story heuristic, not a
    // failure to triage. Synthesising "review candidates" from structural
    // proximity would override that judgment with a noisier guess and
    // double-bill the operator (e.g. opus-4-7 explicitly noting "TS slice
    // is memory-safe" should not be silently re-flagged as CWE-190).
    //
    // Real agent failures (parse errors, timeouts, empty text) take the
    // `invalid_taint_iris_next_agent_result` path in `agent_runtime.rs`,
    // which keeps its own deterministic safety net for that case.
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
