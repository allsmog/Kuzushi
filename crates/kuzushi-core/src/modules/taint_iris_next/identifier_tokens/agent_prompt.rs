use super::*;

pub(in crate::modules::taint_iris_next) fn build_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut lines = vec![
        "Taint IRIS Next".to_string(),
        "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities".to_string(),
        String::new(),
        "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original implementation.".to_string(),
        String::new(),
        "## Objective".to_string(),
        "Use the deterministic context, threat model, CWE catalog, candidates, typed specs, and evidence bundles below to select relevant CWE themes and report only defensible findings.".to_string(),
        format!("minimum finding evidence level: {}", plan.caps.min_evidence_level),
        String::new(),
        "## Backend".to_string(),
        format!("requested: {}", plan.backend.requested),
        format!("selected: {}", plan.backend.selected),
        format!("structural engine: {}", evidence.structural_engine),
        format!("evidence tool: {}", evidence.tool),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        plan.backend
            .codeql_db_path
            .as_ref()
            .map(|path| format!("existing CodeQL DB: {path}"))
            .unwrap_or_else(|| "existing CodeQL DB: none".to_string()),
        String::new(),
        "## Context Summary".to_string(),
        format!("languages: {}", plan.languages.join(", ")),
        format!("context artifact: {}", plan.context_status.reason),
        String::new(),
        "## Threat Model Summary".to_string(),
        format!("threat model artifact: {}", plan.threat_model_status.reason),
        String::new(),
        plan.prompt_catalog.clone(),
        String::new(),
    ];
    if !plan.cwe_focus.is_empty() {
        lines.push("## CWE Focus".to_string());
        lines.push(format!(
            "The operator restricted this hunt to {}. Choose only from these CWEs (the catalog has already been filtered to match) and use customCweRationale only if you discover a clearly different vulnerability class.",
            plan.cwe_focus.join(", ")
        ));
        lines.push(String::new());
    }
    lines.extend(vec![
        "## Candidate And Spec Counts".to_string(),
        format!("candidateCounts: {}", json!(evidence.candidate_counts)),
        format!("labeledSpecCounts: {}", json!(evidence.labeled_spec_counts)),
        String::new(),
        "## Evidence Bundles".to_string(),
    ]);
    for item in evidence.evidence.iter().take(40) {
        lines.push(format!(
            "- {} {} {}:{} [{}] {}",
            item.cwe, item.role, item.file_path, item.line, item.evidence_level, item.snippet
        ));
    }
    lines.push(String::new());
    lines.push("## Linked Stories".to_string());
    for story in evidence.linked_stories.iter().take(20) {
        lines.push(format!(
            "- {} {}:{} -> {} ({})",
            story.cwe, story.file_path, story.source_line, story.sink_line, story.rationale
        ));
    }
    lines.push(String::new());
    lines.push("## Contract".to_string());
    lines.push(
        "- Return strict JSON matching { selectedCwes, findings, triage, notes }.".to_string(),
    );
    lines.push(format!(
        "- Return at most {} findings.",
        plan.caps.max_agent_findings
    ));
    lines.push("- Cite catalogSignals for every selected CWE and every finding.".to_string());
    lines.join("\n")
}
