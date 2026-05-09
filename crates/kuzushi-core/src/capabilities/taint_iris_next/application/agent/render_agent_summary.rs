use super::*;

pub(in crate::capabilities::taint_iris_next) fn push_taint_iris_next_agent_summary(
    lines: &mut Vec<String>,
    agent: &TaintIrisNextAgentResult,
    selected: &[String],
) {
    lines.push(format!("agent status: {}", agent.agent_status));
    lines.push(format!(
        "agent selected CWEs: {}",
        selected_cwe_label(selected)
    ));
    lines.push(format!(
        "triage: findings={} candidates={} rejected={}",
        triage_count(&agent.triage_summary, "finding"),
        triage_count(&agent.triage_summary, "candidate"),
        triage_count(&agent.triage_summary, "rejected")
    ));
    lines.push(format!(
        "findings: {}",
        agent
            .findings
            .len()
            .saturating_sub(agent.review_candidates.len())
    ));
    if !agent.review_candidates.is_empty() {
        lines.push(format!(
            "review candidates: {}",
            agent.review_candidates.len()
        ));
    }
    lines.push(agent_output_status_line(agent));
}

fn selected_cwe_label(selected: &[String]) -> String {
    if selected.is_empty() {
        "none".to_string()
    } else {
        selected.join(", ")
    }
}

fn triage_count(summary: &Value, key: &str) -> u64 {
    summary.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn agent_output_status_line(agent: &TaintIrisNextAgentResult) -> String {
    if agent.structured_output_valid {
        let repair_suffix = if agent.structured_output_retry_count > 0 {
            " after repair retry"
        } else {
            ""
        };
        format!("agent output: valid strict JSON{repair_suffix}")
    } else {
        format!(
            "agent output: invalid strict JSON after {} repair retry",
            agent.structured_output_retry_count
        )
    }
}
