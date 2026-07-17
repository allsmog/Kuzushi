use super::{CanonicalReportArtifact, ReportFailureHandoff};
use crate::run_artifacts::{
    RunArtifact, RunEnvFingerprint, RunHouseRuleFingerprint, RunLlmCallAudit,
    RunPromptOverrideFingerprint, RunSummary, RunTargetGitMetadata,
};

const FAILURE_LIST_RENDER_LIMIT: usize = 12;

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
        format!(
            "- Tool: {}",
            summary.tool.as_deref().unwrap_or("not recorded")
        ),
        format!("- Target: {}", summary.target),
        format!("- Findings: {}", optional_number(summary.findings)),
        format!("- Cost USD: {}", run_cost(summary)),
        String::new(),
    ];
    lines.extend(reproducibility_lines(summary));
    lines.extend(llm_call_lines(&summary.llm_calls));
    lines
}

fn run_cost(summary: &RunSummary) -> String {
    if let Some(cost) = summary.cost_usd {
        return format!("{cost:.6}");
    }
    if summary.provider_spend_unresolved {
        return summary
            .observed_cost_usd
            .map(|cost| format!("observed {cost:.6}; provider spend unresolved"))
            .unwrap_or_else(|| "invalid unresolved receipt".to_string());
    }
    "not recorded".to_string()
}

fn reproducibility_lines(summary: &RunSummary) -> Vec<String> {
    let mut lines = vec!["## Reproducibility".to_string()];
    lines.extend([
        metadata_line("Kuzushi Version", summary.kuzushi_version.as_deref()),
        metadata_line("Platform", summary.platform.as_deref()),
        metadata_line("Model", summary.model.as_deref()),
        metadata_line("Config Hash", summary.config_hash.as_deref()),
        metadata_line("Git SHA", summary.git_sha.as_deref()),
        metadata_line("Git Branch", summary.git_branch.as_deref()),
        metadata_line(
            "Threat Model SHA256",
            summary.threat_model_sha256.as_deref(),
        ),
        target_git_metadata_line(summary.target_git.as_ref()),
    ]);
    lines.push(format!(
        "- House Rules: {}",
        house_rule_metadata(&summary.house_rules)
    ));
    lines.push(format!(
        "- Prompt Overrides: {}",
        prompt_override_metadata(&summary.prompt_overrides)
    ));
    lines.push(format!(
        "- Environment: {}",
        env_fingerprint_metadata(&summary.env_fingerprint)
    ));
    lines.push(String::new());
    lines
}

fn env_fingerprint_metadata(env: &[RunEnvFingerprint]) -> String {
    if env.is_empty() {
        return "not recorded".to_string();
    }
    bounded_metadata_parts(env.iter().map(env_fingerprint_part), env.len())
}

fn target_git_line(git: &RunTargetGitMetadata) -> String {
    let branch = git.branch.as_deref().unwrap_or("detached");
    let dirty = if git.dirty { "dirty" } else { "clean" };
    format!("{} {branch} {dirty}", git.sha)
}

fn target_git_metadata_line(git: Option<&RunTargetGitMetadata>) -> String {
    let Some(git) = git else {
        return metadata_line("Target Git", None);
    };
    let value = target_git_line(git);
    metadata_line("Target Git", Some(&value))
}

fn env_fingerprint_part(env: &RunEnvFingerprint) -> String {
    format!("{} {}", env.key, env.fingerprint)
}

fn prompt_override_metadata(rules: &[RunPromptOverrideFingerprint]) -> String {
    if rules.is_empty() {
        return "not recorded".to_string();
    }
    bounded_metadata_parts(rules.iter().map(prompt_override_part), rules.len())
}

fn prompt_override_part(rule: &RunPromptOverrideFingerprint) -> String {
    format!("{}:{} {}", rule.module, rule.verb, rule.sha256)
}

fn house_rule_metadata(rules: &[RunHouseRuleFingerprint]) -> String {
    if rules.is_empty() {
        return "not recorded".to_string();
    }
    bounded_metadata_parts(rules.iter().map(house_rule_part), rules.len())
}

fn house_rule_part(rule: &RunHouseRuleFingerprint) -> String {
    format!("{} {}", rule.module, rule.sha256)
}

fn bounded_metadata_parts(parts: impl Iterator<Item = String>, total: usize) -> String {
    let mut rendered = parts.take(6).collect::<Vec<_>>();
    if total > 6 {
        rendered.push(format!("... and {} more", total - 6));
    }
    rendered.join(", ")
}

fn metadata_line(label: &str, value: Option<&str>) -> String {
    format!("- {label}: {}", value.unwrap_or("not recorded"))
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
        .map(|artifact| {
            format!(
                "- {} ({}) - {}",
                artifact.label, artifact.kind, artifact.path
            )
        })
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
        return "none".to_string();
    }
    bounded_list(values, FAILURE_LIST_RENDER_LIMIT)
}

fn bounded_list(values: &[String], limit: usize) -> String {
    let mut rendered = values.iter().take(limit).cloned().collect::<Vec<_>>();
    if values.len() > limit {
        rendered.push(format!("... and {} more", values.len() - limit));
    }
    rendered.join(", ")
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
