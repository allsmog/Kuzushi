use super::*;

pub(in crate::capabilities::taint_iris_next) fn taint_iris_next_header_lines(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> Vec<String> {
    vec![
        "Taint IRIS Next".to_string(),
        "IRIS-inspired bounded taint hunting".to_string(),
        String::new(),
        "IRIS-inspired adaptation; not the original IRIS implementation.".to_string(),
        String::new(),
        format!("target: {}", plan.target.display()),
        format!("mode: {}", plan.mode.as_str()),
        format!("outcome: {}", rendered_outcome(evidence, agent)),
        format!(
            "backend: {} -> {}",
            plan.backend.requested, plan.backend.selected
        ),
        format!("structural engine: {}", evidence.structural_engine),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        existing_codeql_db_line(plan),
        format!("scan root: {}", plan.scan_root.display()),
        format!("repo root: {}", plan.repo_root.display()),
        context_status_line(plan),
        threat_model_status_line(plan),
        format!("languages: {}", plan.languages.join(", ")),
        format!("min evidence level: {}", plan.caps.min_evidence_level),
        format!(
            "CWE catalog: {}/{} ranked candidates",
            plan.catalog.len(),
            TAINT_IRIS_NEXT_CATALOG.len()
        ),
        format!("structural query seeds: {}", plan.structural_queries.len()),
        format!("candidates: {}", evidence.candidates.len()),
        format!("labeled specs: {}", evidence.labeled_specs.len()),
        format!("linked stories: {}", evidence.linked_story_count),
        format!("backend paths: {}", evidence.backend_path_count),
        format!(
            "evidence: {} rows via {}",
            evidence.evidence.len(),
            evidence.tool
        ),
    ]
}

fn rendered_outcome(
    evidence: &TaintIrisNextEvidenceResult,
    agent: Option<&TaintIrisNextAgentResult>,
) -> String {
    agent
        .map(|agent| agent.outcome.as_str())
        .unwrap_or(evidence.outcome.as_str())
        .to_string()
}

fn existing_codeql_db_line(plan: &TaintIrisNextPlan) -> String {
    plan.backend
        .codeql_db_path
        .as_ref()
        .map(|path| format!("existing CodeQL DB: {path}"))
        .unwrap_or_else(|| "existing CodeQL DB: none".to_string())
}

fn context_status_line(plan: &TaintIrisNextPlan) -> String {
    format!(
        "context: {} ({})",
        if plan.context_status.ok {
            "loaded"
        } else {
            "missing/incomplete"
        },
        plan.context_status.reason
    )
}

fn threat_model_status_line(plan: &TaintIrisNextPlan) -> String {
    format!(
        "threat model: {} ({})",
        if plan.threat_model_status.ok {
            "loaded"
        } else {
            "warning"
        },
        plan.threat_model_status.reason
    )
}
