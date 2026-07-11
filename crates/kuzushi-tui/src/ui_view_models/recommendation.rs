#[cfg(test)]
use super::ui_latest_run_path;
use super::{attack_surface_risk_model, ui_run_dir, AttackSurfaceRiskModel};
use crate::{app::JsonFileState, ShellApp, ViewDataState};
use kuzushi_core::LatestRunPointerState;
use std::path::{Path, PathBuf};

const RECOMMENDATION_COLUMN_COUNT: usize = 5;
const RECOMMENDATION_REPORT_HEADERS: [&str; 5] =
    ["priority", "tool", "runtime", "signal", "reason"];
const RECOMMENDATION_REPORT_COMMANDS: [&str; 4] =
    ["run <tool> [json]", "trace <run>", "runs", "back"];
const RECOMMENDATION_COMPONENT_COMMANDS: [&str; 4] =
    ["Enter component", "p promote", "run <tool>", "back"];
const RECOMMENDATION_EMPTY_COMMANDS: [&str; 3] = ["recommend", "runs", "back"];
const RECOMMENDATION_TARGETLESS_COMMANDS: [&str; 3] = ["target <path>", "demo", "back"];
const RECOMMENDATION_RUNNING_COMMANDS: [&str; 3] = ["activity", "runs", "back"];

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecommendationModel {
    pub(crate) title: &'static str,
    pub(crate) detail_rows: Vec<RecommendationDetailRow>,
    pub(crate) attack_surface: Option<AttackSurfaceRiskModel>,
    pub(crate) summary: Option<String>,
    pub(crate) report_headers: [&'static str; 5],
    pub(crate) report_commands: [&'static str; 4],
    pub(crate) empty_state: RecommendationEmptyState,
    pub(crate) components: Vec<ComponentRecommendationRow>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentRecommendationRow {
    pub(crate) scope_id: String,
    pub(crate) rel_path: String,
    pub(crate) class_label: String,
    pub(crate) tier_label: String,
    pub(crate) risk_score: u16,
    pub(crate) reason: String,
    pub(crate) scan_input: Option<String>,
    pub(crate) scan_command: String,
    pub(crate) promote_command: Option<String>,
}

pub(crate) fn recommendation_model(app: &ShellApp) -> RecommendationModel {
    let source = RecommendationSource::from_app(app);
    let artifact = source.artifact_json(app, recommendations_artifact_leaf());
    let report = read_recommendations(artifact.clone());
    let source_detail = artifact_detail_label(&source.path, &artifact);
    let components = report
        .as_ref()
        .map(|view| view.components.clone())
        .unwrap_or_default();
    let report_commands = if components.is_empty() {
        RECOMMENDATION_REPORT_COMMANDS
    } else {
        RECOMMENDATION_COMPONENT_COMMANDS
    };
    RecommendationModel {
        title: "RECOMMEND",
        detail_rows: recommendation_detail_rows(
            source_detail,
            source.run_id.clone(),
            source.latest_pointer_invalid,
        ),
        attack_surface: attack_surface_risk_model(source.artifact_json(app, "attack-surface.json")),
        summary: report.as_ref().and_then(|view| view.summary.clone()),
        report_headers: RECOMMENDATION_REPORT_HEADERS,
        report_commands,
        empty_state: recommendation_empty_state(recommender_running(app), app.target().is_some()),
        components,
        rows: report.map(|view| view.rows).unwrap_or_default(),
    }
}

pub(crate) fn recommendation_components(app: &ShellApp) -> Vec<ComponentRecommendationRow> {
    let source = RecommendationSource::from_app(app);
    read_recommendations(source.artifact_json(app, recommendations_artifact_leaf()))
        .map(|view| view.components)
        .unwrap_or_default()
}

pub(crate) fn recommendation_artifact_needs_refresh(app: &ShellApp) -> bool {
    if app.target().is_none() || recommender_running(app) {
        return false;
    }
    let source = RecommendationSource::from_app(app);
    matches!(
        source.artifact_json(app, recommendations_artifact_leaf()),
        JsonFileState::Missing | JsonFileState::NonFile | JsonFileState::Unreadable
    )
}

/// True while the deterministic recommender is in flight, so the view can show
/// a "ranking…" state instead of inviting the operator to (re-)run it.
fn recommender_running(app: &ShellApp) -> bool {
    app.running_tool_name() == Some("module-recommender:recommend")
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

fn recommendation_empty_state(running: bool, has_target: bool) -> RecommendationEmptyState {
    if running {
        return running_recommendation_empty_state();
    }
    if !has_target {
        return targetless_recommendation_empty_state();
    }
    missing_recommendation_empty_state()
}

fn running_recommendation_empty_state() -> RecommendationEmptyState {
    RecommendationEmptyState {
        title: "ranking modules…",
        explanations: [
            "module-recommender:recommend is running for this workspace.",
            "results will appear here automatically when it finishes.",
        ],
        actions: [
            ("(running)", "no action needed — sit tight"),
            ("runs", "inspect persisted runs"),
        ],
        commands: RECOMMENDATION_RUNNING_COMMANDS,
    }
}

fn targetless_recommendation_empty_state() -> RecommendationEmptyState {
    RecommendationEmptyState {
        title: "choose a target first",
        explanations: [
            "recommend ranks modules from the active workspace.",
            "set a repository target or run the offline demo to see a complete flow.",
        ],
        actions: [
            (
                "target <path>",
                "use an existing repository or app directory",
            ),
            (
                "demo",
                "run the bundled offline fixture without credentials",
            ),
        ],
        commands: RECOMMENDATION_TARGETLESS_COMMANDS,
    }
}

fn missing_recommendation_empty_state() -> RecommendationEmptyState {
    RecommendationEmptyState {
        title: "no recommendations artifact",
        explanations: [
            "recommend will run module-recommender:recommend for this workspace.",
            "results appear here after the background run finishes.",
        ],
        actions: [
            (
                "recommend",
                "rank modules for the active workspace and write recommendations.json",
            ),
            ("runs", "inspect persisted runs"),
        ],
        commands: RECOMMENDATION_EMPTY_COMMANDS,
    }
}

fn artifact_detail_label(path: &Path, artifact: &JsonFileState) -> String {
    let display = path.display().to_string();
    match artifact {
        JsonFileState::Present(_) | JsonFileState::Malformed => display,
        JsonFileState::Missing => format!("{display} (missing)"),
        JsonFileState::NonFile => format!("{display} (not a file)"),
        JsonFileState::Unreadable => format!("{display} (unreadable)"),
    }
}

fn read_recommendations(artifact: JsonFileState) -> Option<RecommendationView> {
    let value = match artifact {
        JsonFileState::Present(value) => value,
        JsonFileState::Missing => return None,
        JsonFileState::NonFile => return Some(non_file_recommendations_view()),
        JsonFileState::Malformed | JsonFileState::Unreadable => {
            return Some(malformed_recommendations_view())
        }
    };
    let report = recommendation_report_value(&value);
    Some(RecommendationView {
        summary: string_field(report, "summary"),
        components: component_values(report)
            .into_iter()
            .filter_map(component_from_value)
            .collect(),
        rows: recommendation_values(report)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect(),
    })
}

fn non_file_recommendations_view() -> RecommendationView {
    RecommendationView {
        summary: Some(format!("{} is not a file", recommendations_artifact_leaf())),
        components: Vec::new(),
        rows: vec![RecommendationRow {
            cells: [
                "⚠ high".to_string(),
                recommendations_artifact_leaf().to_string(),
                "no".to_string(),
                "artifact".to_string(),
                "Artifact path is not a file; regenerate recommendations through module-recommender:recommend."
                    .to_string(),
            ],
        }],
    }
}

fn malformed_recommendations_view() -> RecommendationView {
    RecommendationView {
        summary: Some(format!("malformed {}", recommendations_artifact_leaf())),
        components: Vec::new(),
        rows: vec![RecommendationRow {
            cells: [
                "⚠ high".to_string(),
                recommendations_artifact_leaf().to_string(),
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
        .or_else(|| value.pointer("/data/recommendationReport"))
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
        || value
            .get("components")
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

fn component_values(value: &serde_json::Value) -> Vec<serde_json::Value> {
    value
        .get("components")
        .or_else(|| value.pointer("/data/components"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn component_from_value(value: serde_json::Value) -> Option<ComponentRecommendationRow> {
    let next_input = value.get("nextInput");
    let rel_path = string_field(&value, "relPath").or_else(|| string_field(&value, "rel_path"))?;
    let tier_label = string_field(&value, "tier").unwrap_or_else(|| "low".to_string());
    let class_label = string_field(&value, "class").unwrap_or_else(|| "component".to_string());
    Some(ComponentRecommendationRow {
        scope_id: string_field(&value, "scopeId")
            .or_else(|| string_field(&value, "scope_id"))
            .unwrap_or_else(|| rel_path.clone()),
        rel_path: rel_path.clone(),
        class_label,
        risk_score: value
            .get("riskScore")
            .or_else(|| value.get("risk_score"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default() as u16,
        reason: primary_reason(&value).unwrap_or_else(|| "scoped scan candidate".to_string()),
        scan_input: scoped_scan_input(next_input),
        scan_command: scoped_scan_command(next_input),
        promote_command: promote_command(&rel_path, independent_component(&value)),
        tier_label,
    })
}

fn primary_reason(value: &serde_json::Value) -> Option<String> {
    value
        .get("reasons")
        .and_then(serde_json::Value::as_array)?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .find(|reason| !reason.trim().is_empty())
        .map(str::to_string)
}

fn scoped_scan_command(next_input: Option<&serde_json::Value>) -> String {
    scoped_scan_input(next_input)
        .map(|input| format!("run sast:scan {input}"))
        .unwrap_or_else(|| "run sast:scan".to_string())
}

fn scoped_scan_input(next_input: Option<&serde_json::Value>) -> Option<String> {
    next_input.and_then(|input| {
        let mut input = input.clone();
        if let serde_json::Value::Object(object) = &mut input {
            object.remove("target");
            object.remove("component");
        }
        serde_json::to_string(&input).ok()
    })
}

fn independent_component(value: &serde_json::Value) -> bool {
    matches!(
        string_field(value, "class").as_deref(),
        Some("web-app" | "service-api")
    )
}

fn promote_command(rel_path: &str, independent: bool) -> Option<String> {
    independent.then(|| format!("target {rel_path}"))
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
    value
        .get("requiresRuntime")
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
    target: Option<PathBuf>,
    run_id: Option<String>,
    latest_pointer_invalid: bool,
    path: PathBuf,
}

impl RecommendationSource {
    fn from_app(app: &ShellApp) -> Self {
        let Some(root) = app.target() else {
            return Self {
                target: None,
                run_id: None,
                latest_pointer_invalid: false,
                path: ui_run_dir(None, "latest").join(recommendations_artifact_leaf()),
            };
        };
        let latest = match app
            .workbench_cache()
            .borrow()
            .cached_latest_run_pointer(app.target())
        {
            ViewDataState::Ready(latest) => latest,
            ViewDataState::NotRequested | ViewDataState::Loading => LatestRunPointerState::Missing,
        };
        let run_id = match &latest {
            LatestRunPointerState::Ready(run_id) => Some(run_id.as_str().to_string()),
            LatestRunPointerState::Missing | LatestRunPointerState::Invalid(_) => None,
        };
        let run_dir = run_id
            .as_ref()
            .map(|id| ui_run_dir(Some(root), id))
            .unwrap_or_else(|| ui_run_dir(Some(root), "latest"));
        Self {
            target: app.target_path_buf().cloned(),
            run_id,
            latest_pointer_invalid: matches!(latest, LatestRunPointerState::Invalid(_)),
            path: run_dir.join(recommendations_artifact_leaf()),
        }
    }

    fn artifact_json(&self, app: &ShellApp, leaf: &str) -> JsonFileState {
        let (Some(target), Some(run_id)) = (self.target.as_deref(), self.run_id.as_deref()) else {
            return JsonFileState::Missing;
        };
        match app
            .workbench_cache()
            .borrow()
            .cached_run_artifact_json(target, run_id, leaf)
        {
            ViewDataState::Ready(state) => state,
            ViewDataState::NotRequested | ViewDataState::Loading => JsonFileState::Missing,
        }
    }
}

fn recommendations_artifact_leaf() -> &'static str {
    "recommendations.json"
}

struct RecommendationView {
    summary: Option<String>,
    components: Vec<ComponentRecommendationRow>,
    rows: Vec<RecommendationRow>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::ui_latest_run_path;
    use serde_json::json;
    use std::fs;

    fn test_run_dir(root: &Path, run_id: &str) -> PathBuf {
        ui_run_dir(Some(root), run_id)
    }

    fn write_latest_run(root: &Path, run_id: &str) {
        let run_dir = test_run_dir(root, run_id);
        fs::create_dir_all(&run_dir).unwrap();
        let summary =
            kuzushi_core::RunSummary::running(run_id, "tool", None, root.display().to_string());
        fs::write(
            run_dir.join("run.json"),
            serde_json::to_string(&summary).unwrap(),
        )
        .unwrap();
        fs::write(ui_latest_run_path(Some(root)), run_id).unwrap();
    }

    fn create_invalid_latest_pointer(root: &Path) {
        fs::create_dir_all(ui_latest_run_path(Some(root))).unwrap();
    }

    fn write_blank_latest_pointer(root: &Path) {
        let latest_path = ui_latest_run_path(Some(root));
        fs::create_dir_all(latest_path.parent().unwrap()).unwrap();
        fs::write(latest_path, "\n").unwrap();
    }

    #[test]
    fn empty_state_shows_ranking_while_recommender_runs() {
        let running = recommendation_empty_state(true, true);
        assert_eq!(running.title, "ranking modules…");
        // Must NOT invite a re-run while it's already in flight.
        assert!(!running
            .commands
            .iter()
            .any(|c| c.contains("module-recommender")));

        let idle = recommendation_empty_state(false, true);
        assert_eq!(idle.title, "no recommendations artifact");
        assert!(idle.commands.iter().any(|c| *c == "recommend"));

        let targetless = recommendation_empty_state(false, false);
        assert_eq!(targetless.title, "choose a target first");
        assert_eq!(targetless.commands, ["target <path>", "demo", "back"]);
    }

    #[test]
    fn targetless_recommendation_source_does_not_resolve_cwd_as_a_run_root() {
        let app = ShellApp::new(kuzushi_core::V2Config::default(), None);

        let source = RecommendationSource::from_app(&app);

        assert_eq!(source.target, None);
        assert_eq!(source.run_id, None);
        assert!(!source.latest_pointer_invalid);
    }

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
    fn recommendation_from_value_ignores_snake_case_runtime_flag() {
        let row = recommendation_from_value(json!({
            "tool": "triage:run",
            "requires_runtime": true,
            "signals": ["1 persisted finding(s)"]
        }))
        .expect("recommendation row");

        assert_eq!(row.cells[2], "no");
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
            "recommendationReport": {
                "summary": "1 recommendation for /repo",
                "recommendations": [{
                    "tool": "threat-model:build",
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
        let run_dir = test_run_dir(temp.path(), "run-rec");
        fs::create_dir_all(&run_dir).unwrap();
        write_latest_run(temp.path(), "run-rec");
        fs::write(
            run_dir.join(recommendations_artifact_leaf()),
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
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
        let run_dir = test_run_dir(temp.path(), "run-bad-rec");
        fs::create_dir_all(&run_dir).unwrap();
        write_latest_run(temp.path(), "run-bad-rec");
        fs::write(run_dir.join(recommendations_artifact_leaf()), "{not-json").unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let model = recommendation_model(&app);

        assert_eq!(
            model.summary,
            Some(format!("malformed {}", recommendations_artifact_leaf()))
        );
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].cells[1], recommendations_artifact_leaf());
        assert_eq!(model.rows[0].cells[3], "artifact");
        assert!(model.rows[0].cells[4].contains("Malformed JSON"));
    }

    #[test]
    fn recommendation_model_surfaces_non_file_latest_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let run_dir = test_run_dir(temp.path(), "run-unreadable-rec");
        fs::create_dir_all(&run_dir).unwrap();
        write_latest_run(temp.path(), "run-unreadable-rec");
        fs::create_dir(run_dir.join(recommendations_artifact_leaf())).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let model = recommendation_model(&app);

        assert_eq!(
            model.summary,
            Some(format!("{} is not a file", recommendations_artifact_leaf()))
        );
        assert!(model.detail_rows[0].cells[1].ends_with("(not a file)"));
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].cells[1], recommendations_artifact_leaf());
        assert_eq!(model.rows[0].cells[3], "artifact");
        assert!(model.rows[0].cells[4].contains("Artifact path is not a file"));
    }

    #[test]
    fn recommendation_model_surfaces_invalid_latest_pointer() {
        let temp = tempfile::tempdir().unwrap();
        create_invalid_latest_pointer(temp.path());
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
        write_blank_latest_pointer(temp.path());
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

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
            ["priority", "tool", "runtime", "signal", "reason"]
        );
        assert_eq!(
            model.report_commands,
            ["run <tool> [json]", "trace <run>", "runs", "back"]
        );
        assert_eq!(model.empty_state.title, "choose a target first");
        assert_eq!(
            model.empty_state.commands,
            ["target <path>", "demo", "back"]
        );
    }

    #[test]
    fn recommendation_artifact_needs_refresh_only_with_target_and_missing_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        assert!(!recommendation_artifact_needs_refresh(&app));

        app.set_target(Some(temp.path().to_path_buf()));
        assert!(recommendation_artifact_needs_refresh(&app));

        let run_dir = test_run_dir(temp.path(), "run-rec");
        fs::create_dir_all(&run_dir).unwrap();
        write_latest_run(temp.path(), "run-rec");
        fs::write(
            run_dir.join(recommendations_artifact_leaf()),
            serde_json::json!({"recommendations": []}).to_string(),
        )
        .unwrap();
        {
            let mut cache = app.workbench_cache().borrow_mut();
            cache.invalidate_run_summaries();
            cache.invalidate_workspace_files();
        }
        app.invalidate_view_hydration();
        app.hydrate_all_view_data_for_test();

        assert!(!recommendation_artifact_needs_refresh(&app));
    }

    #[test]
    fn recommendation_model_reads_component_recommendations() {
        let temp = tempfile::tempdir().unwrap();
        write_component_recommendation_artifact(temp.path());
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.hydrate_all_view_data_for_test();

        let model = recommendation_model(&app);

        assert_component_recommendation_model(&model);
    }

    fn write_component_recommendation_artifact(target: &Path) {
        let run_dir = test_run_dir(target, "run-components");
        fs::create_dir_all(&run_dir).unwrap();
        write_latest_run(target, "run-components");
        fs::write(
            run_dir.join(recommendations_artifact_leaf()),
            component_recommendation_payload(target).to_string(),
        )
        .unwrap();
    }

    fn component_recommendation_payload(target: &Path) -> serde_json::Value {
        json!({
            "data": {
                "components": [{
                    "scopeId": "package-web",
                    "relPath": "web/app",
                    "class": "web-app",
                    "tier": "high",
                    "riskScore": 91,
                    "reasons": ["web-app component at web/app"],
                    "nextInput": {
                        "target": target.display().to_string(),
                        "paths": ["web/app"],
                        "taskMode": "manual",
                        "tasks": ["semgrep", "dep-hygiene", "secret-scan"]
                    }
                }],
                "recommendations": []
            }
        })
    }

    fn assert_component_recommendation_model(model: &RecommendationModel) {
        assert_eq!(model.components.len(), 1);
        assert_component_recommendation_row(&model.components[0]);
        assert_eq!(
            model.report_commands,
            ["Enter component", "p promote", "run <tool>", "back"]
        );
    }

    fn assert_component_recommendation_row(row: &ComponentRecommendationRow) {
        assert_eq!(row.scope_id, "package-web");
        assert_eq!(row.rel_path, "web/app");
        assert_eq!(row.class_label, "web-app");
        assert!(row
            .scan_input
            .as_deref()
            .is_some_and(|input| input.contains("\"paths\":[\"web/app\"]")));
        assert!(row
            .scan_input
            .as_deref()
            .is_some_and(|input| !input.contains("\"target\"")));
        assert_eq!(row.promote_command.as_deref(), Some("target web/app"));
    }
}
