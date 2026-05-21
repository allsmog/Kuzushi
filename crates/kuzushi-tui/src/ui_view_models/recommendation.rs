use super::{attack_surface_risk_model, AttackSurfaceRiskModel};
use crate::ShellApp;
use std::path::{Path, PathBuf};

const RECOMMENDATION_COLUMN_COUNT: usize = 5;
const RECOMMENDATION_REPORT_HEADERS: [&str; 5] = ["pri", "tool", "runtime", "signal", "reason"];
const RECOMMENDATION_REPORT_COMMANDS: [&str; 4] =
    ["run <tool> [json]", "trace <run>", "runs", "back"];
const RECOMMENDATION_EMPTY_COMMANDS: [&str; 3] =
    ["run module-recommender:recommend", "runs", "back"];

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecommendationModel {
    pub(crate) title: &'static str,
    pub(crate) detail_rows: Vec<RecommendationDetailRow>,
    pub(crate) attack_surface: Option<AttackSurfaceRiskModel>,
    pub(crate) summary: Option<String>,
    pub(crate) report_headers: [&'static str; 5],
    pub(crate) report_commands: [&'static str; 4],
    pub(crate) empty_state: RecommendationEmptyState,
    pub(crate) rows: Vec<RecommendationRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecommendationDetailRow {
    pub(crate) cells: [String; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecommendationEmptyState {
    pub(crate) title: &'static str,
    pub(crate) explanations: [&'static str; 2],
    pub(crate) actions: [(&'static str, &'static str); 2],
    pub(crate) commands: [&'static str; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecommendationRow {
    pub(crate) cells: [String; RECOMMENDATION_COLUMN_COUNT],
}

pub(crate) fn recommendation_model(app: &ShellApp) -> RecommendationModel {
    let source = RecommendationSource::from_app(app);
    let report = read_recommendations(&source.path);
    let source_detail = artifact_detail_label(&source.path);
    RecommendationModel {
        title: "RECOMMEND",
        detail_rows: recommendation_detail_rows(
            source_detail,
            source.run_id,
            source.latest_pointer_invalid,
        ),
        attack_surface: source.path.parent().and_then(attack_surface_risk_model),
        summary: report.as_ref().and_then(|view| view.summary.clone()),
        report_headers: RECOMMENDATION_REPORT_HEADERS,
        report_commands: RECOMMENDATION_REPORT_COMMANDS,
        empty_state: recommendation_empty_state(),
        rows: report.map(|view| view.rows).unwrap_or_default(),
    }
}

fn recommendation_detail_rows(
    source_detail: String,
    run_id: Option<String>,
    latest_pointer_invalid: bool,
) -> Vec<RecommendationDetailRow> {
    let mut rows = vec![recommendation_detail_row("recommendations", source_detail)];
    if latest_pointer_invalid {
        rows.push(recommendation_detail_row(
            "run",
            "invalid latest pointer".to_string(),
        ));
    } else if let Some(run_id) = run_id {
        rows.push(recommendation_detail_row("run", run_id));
    }
    rows
}

fn recommendation_detail_row(label: &str, value: String) -> RecommendationDetailRow {
    RecommendationDetailRow {
        cells: [label.to_string(), value],
    }
}

fn recommendation_empty_state() -> RecommendationEmptyState {
    RecommendationEmptyState {
        title: "no recommendations artifact",
        explanations: [
            "recommend reads the latest recommendations.json artifact.",
            "generate it through normal tool dispatch when planning is needed.",
        ],
        actions: [
            (
                "recommend",
                "ranks modules for the active workspace and writes recommendations.json",
            ),
            ("runs", "inspect persisted runs"),
        ],
        commands: RECOMMENDATION_EMPTY_COMMANDS,
    }
}

fn artifact_detail_label(path: &Path) -> String {
    let display = path.display().to_string();
    if path.exists() {
        display
    } else {
        format!("{display} (missing)")
    }
}

fn read_recommendations(path: &Path) -> Option<RecommendationView> {
    if !path.exists() {
        return None;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return Some(malformed_recommendations_view()),
    };
    let value = match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => value,
        Err(_) => return Some(malformed_recommendations_view()),
    };
    let report = recommendation_report_value(&value);
    Some(RecommendationView {
        summary: string_field(report, "summary"),
        rows: recommendation_values(report)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect(),
    })
}

fn malformed_recommendations_view() -> RecommendationView {
    RecommendationView {
        summary: Some("malformed recommendations.json".to_string()),
        rows: vec![RecommendationRow {
            cells: [
                "⚠ high".to_string(),
                "recommendations.json".to_string(),
                "no".to_string(),
                "artifact".to_string(),
                "Malformed JSON; regenerate recommendations through module-recommender:recommend."
                    .to_string(),
            ],
        }],
    }
}

fn recommendation_report_value(value: &serde_json::Value) -> &serde_json::Value {
    value
        .get("recommendationReport")
        .or_else(|| value.get("recommendation_report"))
        .or_else(|| value.pointer("/data/recommendationReport"))
        .or_else(|| value.pointer("/data/recommendation_report"))
        .or_else(|| recommendation_report_data(value))
        .unwrap_or(value)
}

fn recommendation_report_data(value: &serde_json::Value) -> Option<&serde_json::Value> {
    let data = value.get("data")?;
    has_recommendation_items(data).then_some(data)
}

fn has_recommendation_items(value: &serde_json::Value) -> bool {
    value
        .get("recommendations")
        .and_then(serde_json::Value::as_array)
        .is_some()
}

fn recommendation_values(value: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(items) = value.as_array() {
        return items.clone();
    }
    value
        .get("recommendations")
        .or_else(|| value.pointer("/data/recommendations"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn recommendation_from_value(value: serde_json::Value) -> Option<RecommendationRow> {
    let priority = string_field(&value, "priority");
    Some(RecommendationRow {
        cells: [
            priority_glyph(priority.as_deref().unwrap_or("low")).to_string(),
            string_field(&value, "tool")?,
            runtime_label(requires_runtime(&value)).to_string(),
            primary_signal(&value).unwrap_or_else(|| "-".to_string()),
            string_field(&value, "reason").unwrap_or_else(|| "No reason recorded.".to_string()),
        ],
    })
}

fn requires_runtime(value: &serde_json::Value) -> bool {
    value_at(value, &["requiresRuntime", "requires_runtime"])
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn primary_signal(value: &serde_json::Value) -> Option<String> {
    value
        .get("signals")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|signal| !signal.trim().is_empty())
        .map(str::to_string)
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn value_at<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a serde_json::Value> {
    keys.iter().find_map(|key| value.get(*key))
}

fn priority_glyph(priority: &str) -> &'static str {
    match priority {
        "high" => "⚠ high",
        "medium" => "◆ med",
        _ => "○ low",
    }
}

fn runtime_label(requires_runtime: bool) -> &'static str {
    if requires_runtime {
        "yes"
    } else {
        "no"
    }
}

struct RecommendationSource {
    run_id: Option<String>,
    latest_pointer_invalid: bool,
    path: PathBuf,
}

impl RecommendationSource {
    fn from_app(app: &ShellApp) -> Self {
        let root = app.target.as_deref().unwrap_or_else(|| Path::new("."));
        let latest = recommendation_latest_run_id(root);
        let run_dir = latest
            .run_id
            .as_ref()
            .map(|id| root.join(".kuzushi").join("runs").join(id))
            .unwrap_or_else(|| root.join(".kuzushi/runs/latest"));
        Self {
            run_id: latest.run_id,
            latest_pointer_invalid: latest.invalid,
            path: run_dir.join("recommendations.json"),
        }
    }
}

struct RecommendationLatestRunId {
    run_id: Option<String>,
    invalid: bool,
}

fn recommendation_latest_run_id(root: &Path) -> RecommendationLatestRunId {
    let latest_path = root.join(".kuzushi/latest");
    match std::fs::metadata(&latest_path) {
        Ok(metadata) if metadata.is_file() => recommendation_latest_run_file(&latest_path),
        Ok(_) => RecommendationLatestRunId {
            run_id: None,
            invalid: true,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => RecommendationLatestRunId {
            run_id: None,
            invalid: false,
        },
        Err(_) => RecommendationLatestRunId {
            run_id: None,
            invalid: true,
        },
    }
}

fn recommendation_latest_run_file(path: &Path) -> RecommendationLatestRunId {
    let Ok(text) = std::fs::read_to_string(path) else {
        return RecommendationLatestRunId {
            run_id: None,
            invalid: true,
        };
    };
    let run_id = text.trim();
    if run_id.is_empty() {
        return RecommendationLatestRunId {
            run_id: None,
            invalid: true,
        };
    }
    RecommendationLatestRunId {
        run_id: Some(run_id.to_string()),
        invalid: false,
    }
}

struct RecommendationView {
    summary: Option<String>,
    rows: Vec<RecommendationRow>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    #[test]
    fn recommendation_from_value_shapes_display_row() {
        let row = recommendation_from_value(json!({
            "tool": "semgrep:scan",
            "priority": "high",
            "reason": "Source files match the fast native SAST path.",
            "requiresRuntime": true,
            "signals": ["frameworks: Falcon, Litestar, Sanic"]
        }))
        .expect("recommendation row");

        assert_eq!(
            row,
            RecommendationRow {
                cells: [
                    "⚠ high".to_string(),
                    "semgrep:scan".to_string(),
                    "yes".to_string(),
                    "frameworks: Falcon, Litestar, Sanic".to_string(),
                    "Source files match the fast native SAST path.".to_string(),
                ],
            }
        );
    }

    #[test]
    fn recommendation_from_value_reads_snake_case_runtime_flag() {
        let row = recommendation_from_value(json!({
            "tool": "triage:run",
            "requires_runtime": true,
            "signals": ["1 persisted finding(s)"]
        }))
        .expect("recommendation row");

        assert_eq!(row.cells[2], "yes");
        assert_eq!(row.cells[3], "1 persisted finding(s)");
    }

    #[test]
    fn recommendation_from_value_defaults_optional_display_fields() {
        let row = recommendation_from_value(json!({"tool": "context:build"}))
            .expect("recommendation row");

        assert_eq!(
            row.cells,
            [
                "○ low".to_string(),
                "context:build".to_string(),
                "no".to_string(),
                "-".to_string(),
                "No reason recorded.".to_string(),
            ]
        );
    }

    #[test]
    fn recommendation_values_read_recommendation_report_envelope() {
        let artifact = json!({
            "data": {
                "recommendation_report": {
                    "summary": "1 recommendation for /repo",
                    "recommendations": [{
                        "tool": "threat-model:build",
                        "signals": ["frameworks: Falcon, Litestar, Sanic"]
                    }]
                }
            }
        });
        let report = recommendation_report_value(&artifact);
        let rows = recommendation_values(report)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect::<Vec<_>>();

        assert_eq!(
            string_field(report, "summary").as_deref(),
            Some("1 recommendation for /repo")
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells[1], "threat-model:build");
        assert_eq!(rows[0].cells[3], "frameworks: Falcon, Litestar, Sanic");
    }

    #[test]
    fn recommendation_values_read_data_wrapped_report() {
        let artifact = json!({
            "status": "completed",
            "data": {
                "summary": "1 recommendation for /repo",
                "recommendations": [{
                    "tool": "context:build",
                    "signals": ["frameworks: Falcon, Litestar, Sanic"]
                }]
            }
        });
        let report = recommendation_report_value(&artifact);
        let rows = recommendation_values(report)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect::<Vec<_>>();

        assert_eq!(
            string_field(report, "summary").as_deref(),
            Some("1 recommendation for /repo")
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cells[1], "context:build");
        assert_eq!(rows[0].cells[3], "frameworks: Falcon, Litestar, Sanic");
    }

    #[test]
    fn recommendation_model_reads_data_wrapped_latest_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = temp.path().join(".kuzushi/runs/run-rec");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(temp.path().join(".kuzushi/latest"), "run-rec").unwrap();
        fs::write(
            run_dir.join("recommendations.json"),
            json!({
                "status": "completed",
                "data": {
                    "summary": "1 recommendation for /repo",
                    "recommendations": [{
                        "tool": "threat-model:build",
                        "priority": "medium",
                        "requiresRuntime": false,
                        "reason": "framework route signals exist",
                        "signals": ["frameworks: Falcon, Litestar, Sanic"]
                    }]
                }
            })
            .to_string(),
        )
        .unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = recommendation_model(&app);

        assert_eq!(model.summary.as_deref(), Some("1 recommendation for /repo"));
        assert_eq!(model.detail_rows[1].cells[1], "run-rec");
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].cells[1], "threat-model:build");
        assert_eq!(
            model.rows[0].cells[3],
            "frameworks: Falcon, Litestar, Sanic"
        );
    }

    #[test]
    fn recommendation_model_surfaces_malformed_latest_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = temp.path().join(".kuzushi/runs/run-bad-rec");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(temp.path().join(".kuzushi/latest"), "run-bad-rec").unwrap();
        fs::write(run_dir.join("recommendations.json"), "{not-json").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = recommendation_model(&app);

        assert_eq!(
            model.summary.as_deref(),
            Some("malformed recommendations.json")
        );
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].cells[1], "recommendations.json");
        assert_eq!(model.rows[0].cells[3], "artifact");
        assert!(model.rows[0].cells[4].contains("Malformed JSON"));
    }

    #[test]
    fn recommendation_model_surfaces_unreadable_latest_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = temp.path().join(".kuzushi/runs/run-unreadable-rec");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(temp.path().join(".kuzushi/latest"), "run-unreadable-rec").unwrap();
        fs::create_dir(run_dir.join("recommendations.json")).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = recommendation_model(&app);

        assert_eq!(
            model.summary.as_deref(),
            Some("malformed recommendations.json")
        );
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].cells[1], "recommendations.json");
        assert_eq!(model.rows[0].cells[3], "artifact");
        assert!(model.rows[0].cells[4].contains("Malformed JSON"));
    }

    #[test]
    fn recommendation_model_surfaces_invalid_latest_pointer() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".kuzushi/latest")).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = recommendation_model(&app);

        assert!(model
            .detail_rows
            .iter()
            .any(|row| { row.cells[0] == "run" && row.cells[1] == "invalid latest pointer" }));
        assert!(model.detail_rows[0].cells[1].ends_with("(missing)"));
        assert!(model.rows.is_empty());
    }

    #[test]
    fn recommendation_model_surfaces_blank_latest_pointer() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
        fs::write(temp.path().join(".kuzushi/latest"), "\n").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());

        let model = recommendation_model(&app);

        assert!(model
            .detail_rows
            .iter()
            .any(|row| { row.cells[0] == "run" && row.cells[1] == "invalid latest pointer" }));
        assert!(model.rows.is_empty());
    }

    #[test]
    fn recommendation_model_shapes_static_chrome_and_empty_state() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let model = recommendation_model(&app);

        assert_eq!(model.title, "RECOMMEND");
        assert_eq!(model.detail_rows[0].cells[0], "recommendations");
        assert_eq!(
            model.report_headers,
            ["pri", "tool", "runtime", "signal", "reason"]
        );
        assert_eq!(
            model.report_commands,
            ["run <tool> [json]", "trace <run>", "runs", "back"]
        );
        assert_eq!(model.empty_state.title, "no recommendations artifact");
        assert_eq!(
            model.empty_state.commands,
            ["run module-recommender:recommend", "runs", "back"]
        );
    }
}
