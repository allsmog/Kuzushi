use super::*;

pub(in crate::modules::taint_iris_next) fn render_taint_iris_next_output(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> String {
    let warnings = render_warnings(plan, evidence, agent);
    let selected = selected_agent_cwes(agent);
    let mut lines = taint_iris_next_header_lines(plan, evidence, agent);

    if let Some(agent) = agent {
        push_taint_iris_next_agent_summary(&mut lines, agent, &selected);
    } else {
        push_taint_iris_next_evidence_summary(&mut lines, evidence);
    }

    if !warnings.is_empty() {
        lines.push(format!("warnings: {}", warnings.join("; ")));
    }
    lines.push(String::new());
    lines.push(render_status_line(plan));
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

fn render_status_line(plan: &TaintIrisNextPlan) -> String {
    if plan.mode == TaintIrisNextMode::Plan {
        "Status: deterministic plan complete. Hunt mode will feed this bounded catalog and evidence bundle into one scoped agent session.".to_string()
    } else {
        "Status: hunt complete.".to_string()
    }
}
