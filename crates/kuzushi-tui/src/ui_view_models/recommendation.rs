use super::{attack_surface_risk_model, read_latest_run_id, AttackSurfaceRiskModel};
use crate::ShellApp;
use std::path::{Path, PathBuf};

const RECOMMENDATION_COLUMN_COUNT: usize = 4;
const RECOMMENDATION_REPORT_HEADERS: [&str; 4] = ["pri", "tool", "runtime", "reason"];
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
    pub(crate) report_headers: [&'static str; 4],
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
        detail_rows: recommendation_detail_rows(source_detail, source.run_id),
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
) -> Vec<RecommendationDetailRow> {
    let mut rows = vec![recommendation_detail_row("recommendations", source_detail)];
    if let Some(run_id) = run_id {
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
                "run module-recommender:recommend",
                "writes recommendations.json",
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
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    Some(RecommendationView {
        summary: string_field(&value, "summary"),
        rows: recommendation_values(&value)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect(),
    })
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
            string_field(&value, "reason").unwrap_or_else(|| "No reason recorded.".to_string()),
        ],
    })
}

fn requires_runtime(value: &serde_json::Value) -> bool {
    value
        .get("requiresRuntime")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
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
    path: PathBuf,
}

impl RecommendationSource {
    fn from_app(app: &ShellApp) -> Self {
        let root = app.target.as_deref().unwrap_or_else(|| Path::new("."));
        let run_id = read_latest_run_id(root);
        let run_dir = run_id
            .as_ref()
            .map(|id| root.join(".kuzushi").join("runs").join(id))
            .unwrap_or_else(|| root.join(".kuzushi/runs/latest"));
        Self {
            run_id,
            path: run_dir.join("recommendations.json"),
        }
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

    #[test]
    fn recommendation_from_value_shapes_display_row() {
        let row = recommendation_from_value(json!({
            "tool": "semgrep:scan",
            "priority": "high",
            "reason": "Source files match the fast native SAST path.",
            "requiresRuntime": true
        }))
        .expect("recommendation row");

        assert_eq!(
            row,
            RecommendationRow {
                cells: [
                    "⚠ high".to_string(),
                    "semgrep:scan".to_string(),
                    "yes".to_string(),
                    "Source files match the fast native SAST path.".to_string(),
                ],
            }
        );
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
                "No reason recorded.".to_string(),
            ]
        );
    }

    #[test]
    fn recommendation_model_shapes_static_chrome_and_empty_state() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let model = recommendation_model(&app);

        assert_eq!(model.title, "RECOMMEND");
        assert_eq!(model.detail_rows[0].cells[0], "recommendations");
        assert_eq!(model.report_headers, ["pri", "tool", "runtime", "reason"]);
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
