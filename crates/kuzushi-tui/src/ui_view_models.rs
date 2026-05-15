//! Kuzushi UI view-model boundary.
//!
//! View models are the shaped state consumed by renderers. They are intentionally
//! separate from stores, scanners, and runtime dispatch.

use crate::ShellApp;
use std::path::{Path, PathBuf};

mod attack_surface;
mod failure_handoff;
mod home_cockpit;
mod module_detail;
mod run_timeline;
mod run_trace;
mod threat_model;
pub(crate) use attack_surface::{attack_surface_risk_model, AttackSurfaceRiskModel};
pub(crate) use failure_handoff::failure_handoff_context;
pub(crate) use home_cockpit::{home_cockpit_model, HomeArtifactRow, HomeCockpitModel};
pub(crate) use module_detail::{module_detail_model, ModuleDetailModel};
pub(crate) use run_timeline::{past_runs_model, PastRun, PastRunStatus};
pub(crate) use run_trace::{
    replay_model, trace_model, ReplayModel, RunArtifactDetail, TraceModel, TraceStep,
};
pub(crate) use threat_model::threat_model_doc;

pub use crate::{
    ActivitySession, OptionsFilter, OptionsView, PaneFocus, ReconSnapshot, ScanPanelState,
    ShellView, ThreatView,
};

#[derive(Debug, Clone, PartialEq)]
pub struct RecommendationModel {
    pub source_path: String,
    pub source_detail: String,
    pub run_id: Option<String>,
    pub attack_surface: Option<AttackSurfaceRiskModel>,
    pub summary: Option<String>,
    pub recommendations: Vec<RecommendationRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecommendationRow {
    pub tool: String,
    pub priority: Option<String>,
    pub reason: String,
    pub requires_runtime: bool,
}

pub fn recommendation_model(app: &ShellApp) -> RecommendationModel {
    let source = RecommendationSource::from_app(app);
    let source_path = source.path.display().to_string();
    let report = read_recommendations(&source.path);
    RecommendationModel {
        source_detail: artifact_detail_label(&source.path),
        source_path,
        run_id: source.run_id,
        attack_surface: source.path.parent().and_then(attack_surface_risk_model),
        summary: report.as_ref().and_then(|view| view.summary.clone()),
        recommendations: report.map(|view| view.recommendations).unwrap_or_default(),
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

pub(super) fn read_latest_run_id(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join(".kuzushi/latest"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn read_recommendations(path: &Path) -> Option<RecommendationView> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    Some(RecommendationView {
        summary: string_field(&value, "summary"),
        recommendations: recommendation_values(&value)
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
    Some(RecommendationRow {
        tool: string_field(&value, "tool")?,
        priority: string_field(&value, "priority"),
        reason: string_field(&value, "reason").unwrap_or_else(|| "No reason recorded.".to_string()),
        requires_runtime: value
            .get("requiresRuntime")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
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
    recommendations: Vec<RecommendationRow>,
}
