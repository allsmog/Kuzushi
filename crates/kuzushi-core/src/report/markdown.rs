use super::{CanonicalReportArtifact, ReportFailureHandoff};
use crate::run_artifacts::{RunArtifact, RunLlmCallAudit, RunSummary};

pub(super) fn render_report_markdown(
    summary: &RunSummary,
    canonical: &[CanonicalReportArtifact],
    declared: &[RunArtifact],
    failures: &[ReportFailureHandoff],
) -> String {
    let mut lines = report_header_lines(summary);
    lines.extend(failure_handoff_lines(failures));
    lines.push("## Canonical Artifacts".to_string());
    lines.extend(canonical_artifact_lines(canonical));
    lines.extend(declared_artifact_lines(declared));
    lines.join("\n") + "\n"
}

fn report_header_lines(summary: &RunSummary) -> Vec<String> {
    let mut lines = vec![
        format!("# Kuzushi Run Report - {}", summary.run_id),
        String::new(),
        format!("- Status: {}", summary.status),
        format!("- Tool: {}", summary.tool.as_deref().unwrap_or("not recorded")),
        format!("- Target: {}", summary.target),
        format!("- Findings: {}", optional_number(summary.findings)),
        format!("- Cost USD: {}", optional_cost(summary.cost_usd)),
        String::new(),
    ];
    lines.extend(llm_call_lines(&summary.llm_calls));
    lines
}

fn llm_call_lines(calls: &[RunLlmCallAudit]) -> Vec<String> {
    if calls.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["## LLM Calls".to_string()];
    lines.extend(calls.iter().take(10).map(llm_call_line));
    if calls.len() > 10 {
        lines.push(format!("- ... and {} more", calls.len() - 10));
    }
    lines.push(String::new());
    lines
}

fn llm_call_line(call: &RunLlmCallAudit) -> String {
    format!(
        "- #{} {} {} prompt={} latency={} cost={}",
        call.n,
        call.provider,
        call.model,
        call.prompt_hash,
        optional_number(call.latency_ms),
        optional_cost(call.cost_usd)
    )
}

fn failure_handoff_lines(failures: &[ReportFailureHandoff]) -> Vec<String> {
    if failures.is_empty() {
        return Vec::new();
    }
    let mut lines = vec!["## Failure Handoff".to_string()];
    lines.extend(failures.iter().take(3).flat_map(failure_lines));
    if failures.len() > 3 {
        lines.push(format!("- ... and {} more failure(s)", failures.len() - 3));
    }
    lines.push(String::new());
    lines
}

fn failure_lines(failure: &ReportFailureHandoff) -> Vec<String> {
    vec![
        format!("- Failed Stage: {}", failure.failed_stage),
        format!("- Cause: {}", failure.cause),
        format!("- Available Artifacts: {}", available_artifacts(failure)),
        format!("- Allowed Proof Level: {}", failure.allowed_proof_level),
        format!(
            "- Missing Artifacts: {}",
            list_or_none(&failure.missing_artifacts)
        ),
        format!(
            "- Next Artifacts: {}",
            list_or_none(&failure.next_files_or_artifacts_to_inspect)
        ),
        format!(
            "- Recovery Options: {}",
            list_or_none(&failure.recovery_options)
        ),
        format!("- Fallback Prompt: {}", failure.fallback_prompt),
        format!(
            "- Forbidden Claims: {}",
            list_or_none(&failure.claims_forbidden)
        ),
    ]
}

fn available_artifacts(failure: &ReportFailureHandoff) -> String {
    let paths = failure
        .artifacts_available
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    list_or_none(&paths)
}

fn canonical_artifact_lines(artifacts: &[CanonicalReportArtifact]) -> Vec<String> {
    artifacts
        .iter()
        .map(|artifact| {
            format!(
                "- {}: {} - {}",
                artifact.file,
                artifact_presence(artifact),
                artifact.summary
            )
        })
        .chain([String::new(), "## Declared Artifacts".to_string()])
        .collect()
}

fn declared_artifact_lines(artifacts: &[RunArtifact]) -> Vec<String> {
    if artifacts.is_empty() {
        return vec!["- none recorded".to_string()];
    }
    artifacts
        .iter()
        .map(|artifact| format!("- {} ({}) - {}", artifact.label, artifact.kind, artifact.path))
        .collect()
}

fn artifact_presence(artifact: &CanonicalReportArtifact) -> &'static str {
    if artifact.present {
        "present"
    } else {
        "missing"
    }
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn optional_number(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "not recorded".to_string())
}

fn optional_cost(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.6}"))
        .unwrap_or_else(|| "not recorded".to_string())
}
