use super::*;

pub(in crate::capabilities::taint_iris_next) fn render_taint_iris_next_output(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> String {
    let warnings = render_warnings(plan, evidence, agent);
    let selected = selected_agent_cwes(agent);
    let mut lines = failed_review_notice(agent);
    lines.extend(taint_iris_next_header_lines(plan, evidence, agent));

    if let Some(agent) = agent {
        push_taint_iris_next_agent_summary(&mut lines, agent, &selected);
    } else {
        push_taint_iris_next_evidence_summary(&mut lines, evidence);
    }

    if !warnings.is_empty() {
        lines.push(format!("warnings: {}", warnings.join("; ")));
    }
    lines.push(String::new());
    lines.push(render_status_line(plan, agent));
    lines.push(String::new());
    lines.push(plan.prompt_catalog.clone());
    lines.join("\n")
}

fn render_warnings(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> Vec<String> {
    plan.backend
        .warnings
        .iter()
        .chain(evidence.warnings.iter())
        .chain(agent.into_iter().flat_map(|agent| agent.warnings.iter()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn selected_agent_cwes(agent: Option<&TaintIrisNextAgentResult>) -> Vec<String> {
    agent
        .map(|agent| {
            agent
                .selected_cwes
                .iter()
                .filter_map(|value| value.get("cwe").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn failed_review_notice(agent: Option<&TaintIrisNextAgentResult>) -> Vec<String> {
    let Some(agent) = agent.filter(|agent| !agent.structured_output_valid) else {
        return Vec::new();
    };
    vec![
        "Model review failed. Scan is incomplete.".into(),
        format!(
            "Retained structural candidates: {} (unverified).",
            agent.review_candidates.len()
        ),
        "This attempt remains failed.".into(),
        String::new(),
    ]
}

fn render_status_line(
    plan: &TaintIrisNextPlan,
    agent: Option<&TaintIrisNextAgentResult>,
) -> String {
    if plan.mode == TaintIrisNextMode::Plan {
        return "Status: deterministic plan prepared. No model review or Scan completion. Hunt mode can use an initial session and one repair session within the approved allowance.".into();
    }
    if agent.is_some_and(|agent| !agent.structured_output_valid) {
        return "Status: model review failed. Retained candidates require review. No Scan completion.".into();
    }
    "Status: candidate discovery finished. Observations remain unverified. No Scan completion."
        .into()
}
