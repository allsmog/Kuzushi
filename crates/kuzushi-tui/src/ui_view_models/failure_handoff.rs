use super::{
    ui_latest_run_path, ui_latest_run_relative_path, ui_run_artifact_relative_path, ui_run_dir,
};
use crate::ShellApp;
use kuzushi_core::run_artifacts::{canonical_run_artifact_spec, FailureToLlmContext, RunFailures};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailureHandoffModel {
    pub(crate) rows: Vec<FailureHandoffRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FailureHandoffRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

const FAILURE_MODEL_LIST_LIMIT: usize = 12;
const FAILURE_MODEL_TEXT_LIMIT: usize = 4000;

pub(crate) fn failure_handoff_model(app: &ShellApp) -> Option<FailureHandoffModel> {
    if let Some(context) = live_failure_context(app) {
        return Some(failure_handoff_model_from_context(&context));
    }
    persisted_failure_model(app)
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
                format!(
                    "{} {}",
                    context.artifacts_available.len(),
                    artifact_noun(context.artifacts_available.len()),
                ),
            ),
            failure_row("missing", failure_list(&context.missing_artifacts)),
            failure_row(
                "next",
                failure_list(&context.next_files_or_artifacts_to_inspect),
            ),
            failure_row("recovery", failure_list(&context.recovery_options)),
            failure_row("forbidden", failure_list(&context.claims_forbidden)),
            failure_row("prompt", bounded_failure_text(&context.fallback_prompt)),
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
        return "none".to_string();
    }
    let mut rendered = values
        .iter()
        .take(FAILURE_MODEL_LIST_LIMIT)
        .cloned()
        .collect::<Vec<_>>();
    if values.len() > FAILURE_MODEL_LIST_LIMIT {
        rendered.push(format!("+{} more", values.len() - FAILURE_MODEL_LIST_LIMIT));
    }
    rendered.join(", ")
}

fn artifact_noun(count: usize) -> &'static str {
    if count == 1 {
        "artifact"
    } else {
        "artifacts"
    }
}

fn bounded_failure_text(value: &str) -> String {
    if value.chars().count() <= FAILURE_MODEL_TEXT_LIMIT {
        return value.to_string();
    }
    format!(
        "{}...",
        value
            .chars()
            .take(FAILURE_MODEL_TEXT_LIMIT)
            .collect::<String>()
    )
}

fn live_failure_context(app: &ShellApp) -> Option<FailureToLlmContext> {
    app.agent_chat
        .as_ref()
        .and_then(|agent| agent.failure_context.clone())
}

fn persisted_failure_model(app: &ShellApp) -> Option<FailureHandoffModel> {
    let root = app.target.as_deref()?;
    let latest = failure_latest_run_id(root);
    if latest.invalid {
        return Some(invalid_latest_pointer_model());
    }
    let run_id = latest.run_id?;
    load_latest_failure_model(root, &run_id)
}

fn load_latest_failure_model(root: &Path, run_id: &str) -> Option<FailureHandoffModel> {
    let path = failure_artifact_path(root, run_id);
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Some(non_file_failure_artifact_model(run_id)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(malformed_failure_artifact_model(run_id)),
    }
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(_) => return Some(malformed_failure_artifact_model(run_id)),
    };
    let report = match serde_json::from_str::<RunFailures>(&body) {
        Ok(report) => report,
        Err(_) => return Some(malformed_failure_artifact_model(run_id)),
    };
    report
        .failures
        .into_iter()
        .next()
        .map(|failure| failure_handoff_model_from_context(&failure.agent_thread_context))
}

fn failure_artifact_path(root: &Path, run_id: &str) -> PathBuf {
    ui_run_dir(Some(root), run_id).join(failures_artifact_leaf())
}

struct FailureLatestRunId {
    run_id: Option<String>,
    invalid: bool,
}

fn failure_latest_run_id(root: &Path) -> FailureLatestRunId {
    let latest_path = ui_latest_run_path(Some(root));
    match std::fs::metadata(&latest_path) {
        Ok(metadata) if metadata.is_file() => failure_latest_run_file(&latest_path),
        Ok(_) => FailureLatestRunId {
            run_id: None,
            invalid: true,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => FailureLatestRunId {
            run_id: None,
            invalid: false,
        },
        Err(_) => FailureLatestRunId {
            run_id: None,
            invalid: true,
        },
    }
}

fn failure_latest_run_file(path: &Path) -> FailureLatestRunId {
    let Ok(text) = std::fs::read_to_string(path) else {
        return FailureLatestRunId {
            run_id: None,
            invalid: true,
        };
    };
    let run_id = text.trim();
    if run_id.is_empty() {
        return FailureLatestRunId {
            run_id: None,
            invalid: true,
        };
    }
    FailureLatestRunId {
        run_id: Some(run_id.to_string()),
        invalid: false,
    }
}

fn invalid_latest_pointer_model() -> FailureHandoffModel {
    FailureHandoffModel {
        rows: vec![
            failure_row("stage", "artifact-load".to_string()),
            failure_row("cause", "invalid latest pointer".to_string()),
            failure_row(
                "proof",
                "artifact-review-only; runtime verification did not run".to_string(),
            ),
            failure_row("available", "0 artifacts".to_string()),
            failure_row("missing", failures_artifact_leaf().to_string()),
            failure_row("next", ui_latest_run_relative_path().to_string()),
            failure_row(
                "recovery",
                format!(
                    "Inspect {} and regenerate or repair the latest run pointer.",
                    ui_latest_run_relative_path()
                ),
            ),
            failure_row(
                "forbidden",
                "success, verified, proof confirmed".to_string(),
            ),
            failure_row(
                "prompt",
                "The latest failure handoff artifact could not be selected.".to_string(),
            ),
        ],
    }
}

fn non_file_failure_artifact_model(run_id: &str) -> FailureHandoffModel {
    FailureHandoffModel {
        rows: vec![
            failure_row("stage", "artifact-load".to_string()),
            failure_row(
                "cause",
                format!("{} is not a file", failures_artifact_leaf()),
            ),
            failure_row(
                "proof",
                "artifact-review-only; runtime verification did not run".to_string(),
            ),
            failure_row("available", "0 artifacts".to_string()),
            failure_row("missing", failures_artifact_leaf().to_string()),
            failure_row("next", failure_run_artifact_path(run_id)),
            failure_row(
                "recovery",
                format!(
                    "Regenerate the failed run after removing the invalid {} path.",
                    failures_artifact_leaf()
                ),
            ),
            failure_row(
                "forbidden",
                "success, verified, proof confirmed".to_string(),
            ),
            failure_row(
                "prompt",
                "The latest failure handoff artifact path is not a file.".to_string(),
            ),
        ],
    }
}

fn malformed_failure_artifact_model(run_id: &str) -> FailureHandoffModel {
    FailureHandoffModel {
        rows: vec![
            failure_row("stage", "artifact-load".to_string()),
            failure_row("cause", format!("malformed {}", failures_artifact_leaf())),
            failure_row(
                "proof",
                "artifact-review-only; runtime verification did not run".to_string(),
            ),
            failure_row("available", "0 artifacts".to_string()),
            failure_row("missing", failures_artifact_leaf().to_string()),
            failure_row("next", failure_run_artifact_path(run_id)),
            failure_row(
                "recovery",
                format!(
                    "Inspect {} and regenerate the failed run.",
                    failures_artifact_leaf()
                ),
            ),
            failure_row(
                "forbidden",
                "success, verified, proof confirmed".to_string(),
            ),
            failure_row(
                "prompt",
                "The latest failure handoff artifact could not be parsed.".to_string(),
            ),
        ],
    }
}

fn failure_run_artifact_path(run_id: &str) -> String {
    ui_run_artifact_relative_path(run_id, failures_artifact_leaf())
}

fn failures_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("failures.json")
        .expect("failures artifact must be in shared canonical spec")
        .leaf
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_artifacts::RunArtifact;
    use kuzushi_core::V2Config;

    fn test_run_dir(root: &Path, run_id: &str) -> PathBuf {
        ui_run_dir(Some(root), run_id)
    }

    #[test]
    fn failure_handoff_model_shapes_display_rows() {
        let model = failure_handoff_model_from_context(&FailureToLlmContext {
            failed_stage: " ".to_string(),
            cause: "semgrep binary missing".to_string(),
            what_failed: "semgrep:scan failed".to_string(),
            artifacts_available: vec![RunArtifact {
                label: "run".to_string(),
                path: ui_run_artifact_relative_path("r-1", "run.json"),
                kind: "json".to_string(),
            }],
            missing_artifacts: vec!["findings.json".to_string()],
            allowed_proof_level: "artifact-review-only".to_string(),
            next_files_or_artifacts_to_inspect: vec![failures_artifact_leaf().to_string()],
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
                failure_row("available", "1 artifact".to_string()),
                failure_row("missing", "findings.json".to_string()),
                failure_row("next", failures_artifact_leaf().to_string()),
                failure_row("recovery", "Install semgrep., Rerun scan.".to_string()),
                failure_row("forbidden", "none".to_string()),
                failure_row("prompt", "Continue the failed Kuzushi run.".to_string()),
            ]
        );
    }

    #[test]
    fn failure_handoff_model_bounds_legacy_lists() {
        let model = failure_handoff_model_from_context(&FailureToLlmContext {
            failed_stage: "semgrep:scan".to_string(),
            cause: "scanner failed".to_string(),
            what_failed: "semgrep:scan failed".to_string(),
            artifacts_available: Vec::new(),
            missing_artifacts: numbered_items("missing", 15),
            allowed_proof_level: "artifact-review-only".to_string(),
            next_files_or_artifacts_to_inspect: numbered_items("next", 15),
            recovery_options: numbered_items("recovery", 15),
            fallback_prompt: "Continue the failed Kuzushi run.".to_string(),
            claims_forbidden: numbered_items("claim", 15),
        });

        let missing = row_value(&model, "missing");
        let recovery = row_value(&model, "recovery");
        let forbidden = row_value(&model, "forbidden");

        assert!(missing.contains("missing-11"));
        assert!(!missing.contains("missing-12"));
        assert!(recovery.contains("+3 more"));
        assert!(!forbidden.contains("claim-12"));
    }

    #[test]
    fn failure_handoff_model_surfaces_malformed_failures_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = test_run_dir(temp.path(), "run-bad-failure");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(ui_latest_run_path(Some(temp.path())), "run-bad-failure\n").unwrap();
        std::fs::write(run_dir.join(failures_artifact_leaf()), "{not-json").unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = failure_handoff_model(&app).unwrap();

        assert_eq!(row_value(&model, "stage"), "artifact-load");
        assert_eq!(
            row_value(&model, "cause"),
            format!("malformed {}", failures_artifact_leaf())
        );
        assert_eq!(
            row_value(&model, "next"),
            failure_run_artifact_path("run-bad-failure")
        );
    }

    #[test]
    fn failure_handoff_model_surfaces_non_file_failures_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = test_run_dir(temp.path(), "run-unreadable-failure");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(
            ui_latest_run_path(Some(temp.path())),
            "run-unreadable-failure\n",
        )
        .unwrap();
        std::fs::create_dir(run_dir.join(failures_artifact_leaf())).unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = failure_handoff_model(&app).unwrap();

        assert_eq!(row_value(&model, "stage"), "artifact-load");
        assert_eq!(
            row_value(&model, "cause"),
            format!("{} is not a file", failures_artifact_leaf())
        );
        assert_eq!(
            row_value(&model, "next"),
            failure_run_artifact_path("run-unreadable-failure")
        );
        assert!(row_value(&model, "prompt").contains("path is not a file"));
    }

    #[test]
    fn failure_handoff_model_surfaces_invalid_latest_pointer() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(ui_latest_run_path(Some(temp.path()))).unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = failure_handoff_model(&app).unwrap();

        assert_eq!(row_value(&model, "stage"), "artifact-load");
        assert_eq!(row_value(&model, "cause"), "invalid latest pointer");
        assert_eq!(row_value(&model, "next"), ui_latest_run_relative_path());
    }

    #[test]
    fn failure_handoff_model_surfaces_blank_latest_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let latest_path = ui_latest_run_path(Some(temp.path()));
        std::fs::create_dir_all(latest_path.parent().unwrap()).unwrap();
        std::fs::write(latest_path, "\n").unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = failure_handoff_model(&app).unwrap();

        assert_eq!(row_value(&model, "stage"), "artifact-load");
        assert_eq!(row_value(&model, "cause"), "invalid latest pointer");
        assert_eq!(row_value(&model, "next"), ui_latest_run_relative_path());
    }

    fn row_value<'a>(model: &'a FailureHandoffModel, label: &str) -> &'a str {
        model
            .rows
            .iter()
            .find(|row| row.label == label)
            .map(|row| row.value.as_str())
            .unwrap()
    }

    fn numbered_items(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("{prefix}-{index}"))
            .collect()
    }
}
