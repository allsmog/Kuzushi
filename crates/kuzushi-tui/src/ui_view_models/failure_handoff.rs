use super::{ui_latest_run_relative_path, ui_run_artifact_relative_path};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::run_artifacts::{canonical_run_artifact_spec, FailureToLlmContext, RunFailures};
use kuzushi_core::{LatestRunPointerState, RunArtifactRead};
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
    let mut rows = vec![
        failure_row("stage", failure_text(&context.failed_stage, "unknown")),
        failure_row("cause", failure_text(&context.cause, "unknown")),
    ];
    rows.extend(runtime_failure_rows(context));
    rows.extend(failure_context_rows(context));
    FailureHandoffModel { rows }
}

fn runtime_failure_rows(context: &FailureToLlmContext) -> Vec<FailureHandoffRow> {
    let Some(failure) = context.runtime_failure.as_ref() else {
        return Vec::new();
    };
    let mut rows = vec![failure_row("class", failure.error_class.to_string())];
    push_optional_row(&mut rows, "model", context.model.as_deref());
    push_optional_row(&mut rows, "model stage", failure.stage.as_deref());
    push_optional_row(&mut rows, "call", failure.model_call_id.as_deref());
    if let Some(status) = failure.http_status {
        rows.push(failure_row("http", status.to_string()));
    }
    push_optional_row(&mut rows, "detail", failure.detail.as_deref());
    rows
}

fn push_optional_row(rows: &mut Vec<FailureHandoffRow>, label: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        rows.push(failure_row(label, value.to_string()));
    }
}

fn failure_context_rows(context: &FailureToLlmContext) -> Vec<FailureHandoffRow> {
    vec![
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
        failure_row(
            "recovery",
            failure_list_joined(&context.recovery_options, "\n"),
        ),
        failure_row("forbidden", failure_list(&context.claims_forbidden)),
        failure_row("prompt", bounded_failure_text(&context.fallback_prompt)),
    ]
}

fn failure_row(label: &'static str, value: String) -> FailureHandoffRow {
    FailureHandoffRow { label, value }
}

fn failure_text(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        // Old ledger records doubled the public failure message inside one
        // string; render it once without rewriting persisted data.
        kuzushi_core::run_lifecycle::collapse_repeated_message(value)
    }
}

fn failure_list(values: &[String]) -> String {
    failure_list_joined(values, ", ")
}

fn failure_list_joined(values: &[String], separator: &str) -> String {
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
    rendered.join(separator)
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
    app.agent_chat()
        .and_then(|agent| agent.failure_context.clone())
}

fn persisted_failure_model(app: &ShellApp) -> Option<FailureHandoffModel> {
    let root = app.target()?;
    let latest = match app
        .workbench_cache()
        .borrow()
        .cached_latest_run_pointer(Some(root))
    {
        ViewDataState::Ready(latest) => latest,
        ViewDataState::NotRequested | ViewDataState::Loading => return None,
    };
    match latest {
        LatestRunPointerState::Missing => None,
        LatestRunPointerState::Invalid(_) => Some(invalid_latest_pointer_model()),
        LatestRunPointerState::Ready(run_id) => {
            load_latest_failure_model(app, root, run_id.as_str())
        }
    }
}

fn load_latest_failure_model(
    app: &ShellApp,
    root: &Path,
    run_id: &str,
) -> Option<FailureHandoffModel> {
    let read = match app.workbench_cache().borrow().cached_run_artifact_text(
        root,
        run_id,
        failures_artifact_leaf(),
    ) {
        ViewDataState::Ready(read) => read,
        ViewDataState::NotRequested | ViewDataState::Loading => return None,
    };
    let body = match read {
        RunArtifactRead::Ready { value, .. } => value,
        RunArtifactRead::Missing { .. } => return None,
        RunArtifactRead::NonFile { .. } => return Some(non_file_failure_artifact_model(run_id)),
        RunArtifactRead::Unsafe { .. } | RunArtifactRead::Unreadable { .. } => {
            return Some(malformed_failure_artifact_model(run_id))
        }
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
    use crate::ui_view_models::{ui_latest_run_path, ui_run_dir};
    use kuzushi_core::run_artifacts::{
        record_tool_run_failed, record_tool_run_started, RunArtifact, ToolRunRecord,
    };
    use kuzushi_core::V2Config;
    use std::path::PathBuf;

    fn test_run_dir(root: &Path, run_id: &str) -> PathBuf {
        ui_run_dir(Some(root), run_id)
    }

    fn write_latest_run(root: &Path, run_id: &str) {
        let run_dir = test_run_dir(root, run_id);
        std::fs::create_dir_all(&run_dir).unwrap();
        let summary =
            kuzushi_core::RunSummary::running(run_id, "tool", None, root.display().to_string());
        std::fs::write(
            run_dir.join("run.json"),
            serde_json::to_string(&summary).unwrap(),
        )
        .unwrap();
        std::fs::write(ui_latest_run_path(Some(root)), format!("{run_id}\n")).unwrap();
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
            resume_from: None,
            completed_stages: Vec::new(),
            checkpoint_artifacts: Vec::new(),
            checkpoint_fingerprint: None,
            runtime_failure: None,
            model: None,
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
                failure_row("recovery", "Install semgrep.\nRerun scan.".to_string()),
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
            resume_from: None,
            completed_stages: Vec::new(),
            checkpoint_artifacts: Vec::new(),
            checkpoint_fingerprint: None,
            runtime_failure: None,
            model: None,
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
    fn failure_handoff_model_reads_failed_tool_run_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "run-failed-tool-handoff";
        let record = ToolRunRecord::new(temp.path(), run_id, "tool", "agentic-sast:scan");
        record_tool_run_started(record, &serde_json::json!({"target": "."}));
        record_tool_run_failed(record, "bridge failed");

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let model = failure_handoff_model(&app).unwrap();

        assert_eq!(row_value(&model, "stage"), "agentic-sast:scan");
        assert_eq!(row_value(&model, "cause"), "bridge failed");
        assert!(row_value(&model, "proof").contains("artifact-review-only"));
        assert_eq!(row_value(&model, "available"), "7 artifacts");
        assert_eq!(row_value(&model, "missing"), "none");
        assert!(row_value(&model, "next").contains("failures.json"));
        assert!(row_value(&model, "recovery").contains("Rerun agentic-sast:scan"));
        assert!(row_value(&model, "forbidden").contains("verified claim"));
        assert!(row_value(&model, "prompt")
            .contains("Continue the failed Kuzushi run for agentic-sast:scan"));
    }

    #[test]
    fn failure_handoff_model_surfaces_malformed_failures_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = test_run_dir(temp.path(), "run-bad-failure");
        write_latest_run(temp.path(), "run-bad-failure");
        std::fs::write(run_dir.join(failures_artifact_leaf()), "{not-json").unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
        write_latest_run(temp.path(), "run-unreadable-failure");
        std::fs::create_dir(run_dir.join(failures_artifact_leaf())).unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
