use super::super::*;
use super::coverage::CoverageGap;

pub(crate) struct GapFillOutcome {
    pub(crate) added_threats: usize,
    pub(crate) added_deprioritized: usize,
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
}

/// Stage G: one bounded STRIDE pass over ONLY the uncovered entry points.
/// Gap-fill threats are forced to empty evidence deterministically — "at
/// least one threat with empty evidence, or this stage didn't run".
pub(crate) fn run_gap_fill(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    verb: &str,
    gaps: &[CoverageGap],
    document: &mut Value,
) -> Result<GapFillOutcome> {
    let prompt = gap_fill_prompt(input, gaps);
    let costed = query_gap_fill(runtime, ctx, input, verb, gaps.len(), prompt)?;
    let outcome = merge_gap_fill(document, &costed.value, costed.cost_usd, costed.cost_usd_exact);
    Ok(outcome)
}

fn query_gap_fill(
    runtime: &dyn AgentRuntime,
    ctx: &ToolExecutionContext<'_>,
    input: &BuildInput,
    verb: &str,
    gap_count: usize,
    prompt: String,
) -> Result<crate::structured_output::CostedStructuredJson<Value>> {
    let _scope = begin_gap_fill_scope(ctx, verb, gap_count);
    crate::structured_output::query_required_structured_json_with_cost(
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            threat_model_system_prompt(),
            prompt,
        ),
        StructuredJsonContract::new("threat-model:build", "ThreatModelGapFill", gap_fill_schema()),
        Ok,
    )
}

fn begin_gap_fill_scope(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    gap_count: usize,
) -> Option<crate::run_artifacts::ParentScope> {
    ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                format!("gap-fill: {gap_count} uncovered entry points (STRIDE)"),
            )
            .emit();
        trace.parent_scope(phase)
    })
}

fn gap_fill_schema() -> Value {
    json!({
        "type": "object",
        "required": ["threats", "deprioritized"],
        "additionalProperties": false,
        "properties": {
            "threats": {"type": "array", "items": {"type": "object"}},
            "deprioritized": {"type": "array", "items": {"type": "object"}}
        }
    })
}

fn gap_fill_prompt(input: &BuildInput, gaps: &[CoverageGap]) -> String {
    let gap_lines = gaps
        .iter()
        .map(|gap| format!("- {} ({})", gap.entry_point, gap.path))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"A deterministic coverage check found ground-truth entry points with neither a threat nor a deprioritized row in the threat model for {repo}.

Uncovered entry points:
{gap_lines}

For EACH entry point above, walk STRIDE (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) and either:
- add the plausible threats as objects with the standard threat shape (id, targetElementIds, category, title, description, actor, surface, asset, attackVector, preconditions, impact, likelihood, status, existingMitigations, missingMitigations, recommendedMitigation, relatedCwe, affectedFiles) where `surface` names the entry point verbatim and `affectedFiles` cites its path; or
- add a deprioritized row {{"entryPoint": "<name>", "reason": "<why no material threat>"}}.

Rules:
- Gap-fill threats have NO past-vuln evidence: leave `evidence` empty (it is stripped deterministically).
- Score likelihood from technique prevalence and reachability alone.
- Cover every listed entry point; do not add threats for surfaces not listed.

Return one JSON object: {{"threats": [...], "deprioritized": [...]}}."#,
        repo = input.repo_name,
    )
}

fn merge_gap_fill(
    document: &mut Value,
    response: &Value,
    cost_usd: f64,
    cost_usd_exact: bool,
) -> GapFillOutcome {
    let threats = sanitized_gap_threats(response);
    let deprioritized = response
        .get("deprioritized")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let outcome = GapFillOutcome {
        added_threats: threats.len(),
        added_deprioritized: deprioritized.len(),
        cost_usd,
        cost_usd_exact,
    };
    append_rows(document, "threats", threats);
    append_rows(document, "deprioritized", deprioritized);
    outcome
}

fn sanitized_gap_threats(response: &Value) -> Vec<Value> {
    response
        .get("threats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|mut threat| {
            threat["evidence"] = json!([]);
            threat["gapFill"] = json!(true);
            threat
        })
        .collect()
}

fn append_rows(document: &mut Value, key: &str, rows: Vec<Value>) {
    if rows.is_empty() {
        return;
    }
    if !document.get(key).is_some_and(Value::is_array) {
        document[key] = json!([]);
    }
    if let Some(existing) = document.get_mut(key).and_then(Value::as_array_mut) {
        existing.extend(rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_fill_threats_are_stripped_of_invented_evidence_and_marked() {
        let mut document = json!({"threats": [{"id": "T-1"}], "deprioritized": []});
        let response = json!({
            "threats": [{
                "id": "T-GAP-1",
                "surface": "GET /admin/debug",
                "evidence": [{"kind": "commit", "ref": "invented", "summary": "no"}]
            }],
            "deprioritized": [{"entryPoint": "GET /health", "reason": "no data"}]
        });
        let outcome = merge_gap_fill(&mut document, &response, 0.1, true);
        assert_eq!(outcome.added_threats, 1);
        assert_eq!(outcome.added_deprioritized, 1);
        let added = &document["threats"][1];
        assert_eq!(added["evidence"], json!([]));
        assert_eq!(added["gapFill"], json!(true));
        assert_eq!(document["deprioritized"][0]["entryPoint"], json!("GET /health"));
    }
}
