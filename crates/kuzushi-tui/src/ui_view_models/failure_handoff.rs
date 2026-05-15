use crate::ShellApp;
use kuzushi_core::run_artifacts::{load_run_failure_context, FailureToLlmContext};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailureHandoffModel {
    pub(crate) rows: Vec<FailureHandoffRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailureHandoffRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

pub(crate) fn failure_handoff_model(app: &ShellApp) -> Option<FailureHandoffModel> {
    failure_handoff_context(app).map(|context| failure_handoff_model_from_context(&context))
}

pub(super) fn failure_handoff_model_from_context(
    context: &FailureToLlmContext,
) -> FailureHandoffModel {
    FailureHandoffModel {
        rows: vec![
            failure_row("stage", failure_text(&context.failed_stage, "unknown")),
            failure_row("cause", failure_text(&context.cause, "unknown")),
            failure_row("proof", context.allowed_proof_level.clone()),
            failure_row(
                "available",
                format!("{} artifact(s)", context.artifacts_available.len()),
            ),
            failure_row("missing", failure_list(&context.missing_artifacts)),
            failure_row(
                "next",
                failure_list(&context.next_files_or_artifacts_to_inspect),
            ),
            failure_row("recovery", context.recovery_options.join(" | ")),
            failure_row("forbidden", failure_list(&context.claims_forbidden)),
            failure_row("prompt", context.fallback_prompt.clone()),
        ],
    }
}

fn failure_row(label: &'static str, value: String) -> FailureHandoffRow {
    FailureHandoffRow { label, value }
}

fn failure_text(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn failure_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn failure_handoff_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    live_failure_context(app).or_else(|| persisted_failure_context(app))
}

fn live_failure_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    app.agent_chat
        .as_ref()
        .and_then(|agent| agent.failure_context.clone())
}

fn persisted_failure_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    let root = app.target.as_deref()?;
    let run_id = super::read_latest_run_id(root)?;
    load_latest_failure_context(root, &run_id)
}

fn load_latest_failure_context(root: &Path, run_id: &str) -> Option<FailureToLlmContext> {
    load_run_failure_context(root, run_id).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_artifacts::RunArtifact;

    #[test]
    fn failure_handoff_model_shapes_display_rows() {
        let model = failure_handoff_model_from_context(&FailureToLlmContext {
            failed_stage: " ".to_string(),
            cause: "semgrep binary missing".to_string(),
            what_failed: "semgrep:scan failed".to_string(),
            artifacts_available: vec![RunArtifact {
                label: "run".to_string(),
                path: ".kuzushi/runs/r-1/run.json".to_string(),
                kind: "json".to_string(),
            }],
            missing_artifacts: vec!["findings.json".to_string()],
            allowed_proof_level: "artifact-review-only".to_string(),
            next_files_or_artifacts_to_inspect: vec!["failures.json".to_string()],
            recovery_options: vec!["Install semgrep.".to_string(), "Rerun scan.".to_string()],
            fallback_prompt: "Continue the failed Kuzushi run.".to_string(),
            claims_forbidden: Vec::new(),
        });

        assert_eq!(
            model.rows,
            vec![
                failure_row("stage", "unknown".to_string()),
                failure_row("cause", "semgrep binary missing".to_string()),
                failure_row("proof", "artifact-review-only".to_string()),
                failure_row("available", "1 artifact(s)".to_string()),
                failure_row("missing", "findings.json".to_string()),
                failure_row("next", "failures.json".to_string()),
                failure_row("recovery", "Install semgrep. | Rerun scan.".to_string()),
                failure_row("forbidden", "none".to_string()),
                failure_row("prompt", "Continue the failed Kuzushi run.".to_string()),
            ]
        );
    }
}
