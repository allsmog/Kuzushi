use super::{attack_surface_risk_model, ui_latest_run_path, ui_run_dir, AttackSurfaceRiskModel};
use crate::ShellApp;
use kuzushi_core::run_artifacts::{
    canonical_run_artifact_spec, canonical_run_artifact_specs, RunArtifactSpec,
};
use std::path::{Path, PathBuf};

const HOME_TIMELINE_ARTIFACTS: [&str; 3] = ["run.json", "events.jsonl", "trace.jsonl"];
const HOME_ARTIFACT_COLUMN_COUNT: usize = 4;
const HOME_COMMANDS: [&str; 6] = [
    "modules",
    "recommend",
    "quickstart",
    "scan .",
    "findings",
    "runs",
];

#[derive(Debug, Clone, PartialEq)]
pub struct HomeCockpitModel {
    pub title: &'static str,
    pub summary_rows: Vec<HomeSummaryRow>,
    pub attack_surface: Option<AttackSurfaceRiskModel>,
    pub next_action: String,
    pub rail_legend: &'static str,
    pub command_labels: [&'static str; 6],
    pub artifacts: Vec<HomeArtifactRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HomeSummaryRow {
    pub cells: [String; 2],
}

#[derive(Debug, Clone, PartialEq)]
pub struct HomeArtifactRow {
    pub cells: [String; HOME_ARTIFACT_COLUMN_COUNT],
}

pub fn home_cockpit_model(app: &ShellApp) -> HomeCockpitModel {
    let run = HomeRunModel::from_app(app);
    let target = target_label(app);
    let latest_run = run.latest_run_label();
    let run_status = run_status_label(&run.run_dir);
    let module_count = app.registry.modules().count();
    let finding_count = app.findings.len();
    HomeCockpitModel {
        title: "HOME",
        summary_rows: home_summary_rows(
            target,
            latest_run,
            run_status,
            module_count,
            finding_count,
        ),
        attack_surface: attack_surface_risk_model(&run.run_dir),
        next_action: home_next_action(app),
        rail_legend:
            "rails: ✓ recorded · ○ placeholder · ◆ partial · ⚠ failed/malformed · ■ missing",
        command_labels: HOME_COMMANDS,
        artifacts: home_artifact_rows(&run.run_dir),
    }
}

fn home_summary_rows(
    target: String,
    latest_run: String,
    run_status: String,
    module_count: usize,
    finding_count: usize,
) -> Vec<HomeSummaryRow> {
    vec![
        home_summary_row("target", target),
        home_summary_row("latest run", latest_run),
        home_summary_row("run status", run_status),
        home_summary_row("modules", module_count.to_string()),
        home_summary_row("findings", finding_count.to_string()),
    ]
}

fn home_summary_row(label: &str, value: String) -> HomeSummaryRow {
    HomeSummaryRow {
        cells: [label.to_string(), value],
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
        return "Run `scan .` to scan the current directory and create the first run artifacts."
            .to_string();
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
    canonical_run_artifact_specs()
        .into_iter()
        .filter(home_artifact_belongs_in_rail)
        .map(|artifact| home_artifact_row(run_dir, artifact))
        .collect()
}

fn home_artifact_belongs_in_rail(artifact: &RunArtifactSpec) -> bool {
    !HOME_TIMELINE_ARTIFACTS.contains(&artifact.leaf)
}

fn home_artifact_row(run_dir: &Path, artifact: RunArtifactSpec) -> HomeArtifactRow {
    let path = run_dir.join(artifact.leaf);
    let state = artifact_state(&path, &artifact);
    HomeArtifactRow {
        cells: [
            state.glyph.to_string(),
            home_artifact_label(artifact.label).to_string(),
            state.label.to_string(),
            path.display().to_string(),
        ],
    }
}

fn artifact_state(path: &Path, artifact: &RunArtifactSpec) -> HomeArtifactState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return HomeArtifactState::non_file(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return HomeArtifactState::missing();
        }
        Err(_) => return HomeArtifactState::malformed(),
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return HomeArtifactState::malformed();
    };
    if is_json_artifact(artifact) {
        return artifact_state_from_json_text(&text);
    }
    artifact_state_from_text(&text)
}

fn artifact_state_from_json_text(text: &str) -> HomeArtifactState {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return HomeArtifactState::malformed();
    };
    artifact_status_from_value(&value)
        .and_then(|status| state_for_status(&status))
        .unwrap_or_else(HomeArtifactState::recorded)
}

fn artifact_state_from_text(text: &str) -> HomeArtifactState {
    artifact_status(text)
        .and_then(|status| state_for_status(&status))
        .unwrap_or_else(|| state_for_unstructured_artifact(text))
}

fn artifact_status(text: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(text).ok()?;
    artifact_status_from_value(&value)
}

fn artifact_status_from_value(value: &serde_json::Value) -> Option<String> {
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
    let path = run_dir.join(run_metadata_artifact_leaf());
    match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return format!("{} is not a file", run_metadata_artifact_leaf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return "no runs yet".to_string();
        }
        Err(_) => return malformed_run_metadata_label(),
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return malformed_run_metadata_label();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return malformed_run_metadata_label();
    };
    if !value.is_object() {
        return malformed_run_metadata_label();
    }
    value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| "status unknown".to_string())
}

fn malformed_run_metadata_label() -> String {
    format!("malformed {}", run_metadata_artifact_leaf())
}

fn run_metadata_artifact_leaf() -> &'static str {
    canonical_run_artifact_spec("run.json")
        .expect("run metadata artifact must be in shared canonical spec")
        .leaf
}

fn home_artifact_label(label: &str) -> &str {
    match label {
        "context snapshot" => "ctx",
        "attack surface" => "surface",
        "threat model" => "threat",
        "recommendations" => "recommend",
        "failure handoff" => "failures",
        "artifact manifest" => "manifest",
        _ => label,
    }
}

fn is_json_artifact(artifact: &RunArtifactSpec) -> bool {
    artifact.kind == "json" || artifact.leaf.ends_with(".json")
}

struct HomeRunModel {
    run_id: Option<String>,
    latest_pointer_invalid: bool,
    run_dir: PathBuf,
}

impl HomeRunModel {
    fn from_app(app: &ShellApp) -> Self {
        let Some(root) = app.target.as_ref() else {
            return Self {
                run_id: None,
                latest_pointer_invalid: false,
                run_dir: ui_run_dir(None, "latest"),
            };
        };
        let latest = home_latest_run_id(root);
        let run_dir = latest
            .run_id
            .as_ref()
            .map(|id| ui_run_dir(Some(root), id))
            .unwrap_or_else(|| ui_run_dir(Some(root), "latest"));
        Self {
            run_id: latest.run_id,
            latest_pointer_invalid: latest.invalid,
            run_dir,
        }
    }

    fn latest_run_label(&self) -> String {
        if self.latest_pointer_invalid {
            "invalid latest pointer".to_string()
        } else {
            self.run_id.clone().unwrap_or_else(|| "none".to_string())
        }
    }
}

struct HomeLatestRunId {
    run_id: Option<String>,
    invalid: bool,
}

fn home_latest_run_id(root: &Path) -> HomeLatestRunId {
    let latest_path = ui_latest_run_path(Some(root));
    match std::fs::metadata(&latest_path) {
        Ok(metadata) if metadata.is_file() => home_latest_run_file(&latest_path),
        Ok(_) => HomeLatestRunId {
            run_id: None,
            invalid: true,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => HomeLatestRunId {
            run_id: None,
            invalid: false,
        },
        Err(_) => HomeLatestRunId {
            run_id: None,
            invalid: true,
        },
    }
}

fn home_latest_run_file(path: &Path) -> HomeLatestRunId {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HomeLatestRunId {
            run_id: None,
            invalid: true,
        };
    };
    let run_id = text.trim();
    if run_id.is_empty() {
        return HomeLatestRunId {
            run_id: None,
            invalid: true,
        };
    }
    HomeLatestRunId {
        run_id: Some(run_id.to_string()),
        invalid: false,
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

    const fn malformed() -> Self {
        Self::new("⚠", "malformed")
    }

    const fn non_file() -> Self {
        Self::new("⚠", "not a file")
    }
}

#[cfg(test)]
mod tests;
