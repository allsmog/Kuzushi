use super::{attack_surface_risk_model, read_latest_run_id, AttackSurfaceRiskModel};
use crate::ShellApp;
use std::path::{Path, PathBuf};

const HOME_ARTIFACTS: &[HomeArtifactSpec] = &[
    HomeArtifactSpec::new("ctx", "context.json"),
    HomeArtifactSpec::new("surface", "attack-surface.json"),
    HomeArtifactSpec::new("threat", "threat-model.json"),
    HomeArtifactSpec::new("recommend", "recommendations.json"),
    HomeArtifactSpec::new("findings", "findings.json"),
    HomeArtifactSpec::new("proof", "proof.json"),
    HomeArtifactSpec::new("failures", "failures.json"),
    HomeArtifactSpec::new("report", "report.md"),
];

#[derive(Debug, Clone, PartialEq)]
pub struct HomeCockpitModel {
    pub target: String,
    pub latest_run: String,
    pub run_status: String,
    pub attack_surface: Option<AttackSurfaceRiskModel>,
    pub module_count: usize,
    pub finding_count: usize,
    pub next_action: String,
    pub artifacts: Vec<HomeArtifactRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HomeArtifactRow {
    pub label: &'static str,
    pub path: String,
    pub glyph: &'static str,
    pub state: &'static str,
}

pub fn home_cockpit_model(app: &ShellApp) -> HomeCockpitModel {
    let run = HomeRunModel::from_app(app);
    HomeCockpitModel {
        target: target_label(app),
        latest_run: run.run_id.clone().unwrap_or_else(|| "none".to_string()),
        run_status: run_status_label(&run.run_dir),
        attack_surface: attack_surface_risk_model(&run.run_dir),
        module_count: app.registry.modules().count(),
        finding_count: app.findings.len(),
        next_action: home_next_action(app),
        artifacts: home_artifact_rows(&run.run_dir),
    }
}

fn target_label(app: &ShellApp) -> String {
    app.target
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn home_next_action(app: &ShellApp) -> String {
    if app.target.is_none() {
        return "Run scan . to create the first Kuzushi run artifacts.".to_string();
    }
    if app.findings.is_empty() {
        return format!(
            "Run {} to populate findings and proof rails.",
            app.first_finding_scan_command()
        );
    }
    "Open findings, recommend, or runs to continue from recorded artifacts.".to_string()
}

fn home_artifact_rows(run_dir: &Path) -> Vec<HomeArtifactRow> {
    HOME_ARTIFACTS
        .iter()
        .map(|artifact| home_artifact_row(run_dir, artifact))
        .collect()
}

fn home_artifact_row(run_dir: &Path, artifact: &HomeArtifactSpec) -> HomeArtifactRow {
    let path = run_dir.join(artifact.leaf);
    let state = artifact_state(&path);
    HomeArtifactRow {
        label: artifact.label,
        path: path.display().to_string(),
        glyph: state.glyph,
        state: state.label,
    }
}

fn artifact_state(path: &Path) -> HomeArtifactState {
    if !path.exists() {
        return HomeArtifactState::missing();
    }
    let text = std::fs::read_to_string(path).unwrap_or_default();
    artifact_state_from_text(&text)
}

fn artifact_state_from_text(text: &str) -> HomeArtifactState {
    artifact_status(text)
        .and_then(|status| state_for_status(&status))
        .unwrap_or_else(|| state_for_unstructured_artifact(text))
}

fn artifact_status(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    value
        .get("status")
        .or_else(|| value.pointer("/summary/status"))
        .and_then(serde_json::Value::as_str)
        .map(|status| status.to_ascii_lowercase())
}

fn state_for_status(status: &str) -> Option<HomeArtifactState> {
    match status {
        "completed" | "complete" | "ok" => Some(HomeArtifactState::recorded()),
        "partial" => Some(HomeArtifactState::partial()),
        "failed" | "error" => Some(HomeArtifactState::failed()),
        "skipped" => Some(HomeArtifactState::placeholder()),
        _ => None,
    }
}

fn state_for_unstructured_artifact(text: &str) -> HomeArtifactState {
    if text.contains("No report was recorded") {
        return HomeArtifactState::placeholder();
    }
    HomeArtifactState::recorded()
}

fn run_status_label(run_dir: &Path) -> String {
    std::fs::read_to_string(run_dir.join("run.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("status")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "no run.json".to_string())
}

struct HomeArtifactSpec {
    label: &'static str,
    leaf: &'static str,
}

impl HomeArtifactSpec {
    const fn new(label: &'static str, leaf: &'static str) -> Self {
        Self { label, leaf }
    }
}

struct HomeRunModel {
    run_id: Option<String>,
    run_dir: PathBuf,
}

impl HomeRunModel {
    fn from_app(app: &ShellApp) -> Self {
        let Some(root) = app.target.as_ref() else {
            return Self {
                run_id: None,
                run_dir: PathBuf::from(".kuzushi/runs/latest"),
            };
        };
        let run_id = read_latest_run_id(root);
        let run_dir = run_id
            .as_ref()
            .map(|id| root.join(".kuzushi").join("runs").join(id))
            .unwrap_or_else(|| root.join(".kuzushi/runs/latest"));
        Self { run_id, run_dir }
    }
}

struct HomeArtifactState {
    glyph: &'static str,
    label: &'static str,
}

impl HomeArtifactState {
    const fn new(glyph: &'static str, label: &'static str) -> Self {
        Self { glyph, label }
    }

    const fn recorded() -> Self {
        Self::new("✓", "recorded")
    }

    const fn placeholder() -> Self {
        Self::new("○", "placeholder")
    }

    const fn failed() -> Self {
        Self::new("⚠", "failed")
    }

    const fn missing() -> Self {
        Self::new("■", "missing")
    }

    const fn partial() -> Self {
        Self::new("◆", "partial")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_state_maps_home_rail_glyphs() {
        assert_eq!(
            artifact_state_from_text(r#"{"status":"completed"}"#).label,
            "recorded"
        );
        assert_eq!(
            artifact_state_from_text(r#"{"status":"skipped"}"#).label,
            "placeholder"
        );
        assert_eq!(
            artifact_state_from_text(r#"{"status":"failed"}"#).label,
            "failed"
        );
        assert_eq!(
            artifact_state_from_text(r#"{"status":"partial"}"#).label,
            "partial"
        );
        assert_eq!(
            artifact_state_from_text("No report was recorded for this run.").label,
            "placeholder"
        );
    }
}
