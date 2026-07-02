use super::findings::{cached_sorted_finding_alias_indices, relativize_location, target_base};
use super::journey::is_reviewed_finding;
use super::{
    attack_surface_risk_model, context_snapshot_state, journey_model, ui_latest_run_path,
    ui_run_dir, AttackSurfaceRiskModel, JourneyModel, SeverityCounts, SeverityTone,
};
use crate::ShellApp;
use kuzushi_core::run_artifacts::{
    canonical_run_artifact_spec, canonical_run_artifact_specs, RunArtifactSpec,
};
use kuzushi_core::{project_finding, Finding};
use std::path::{Path, PathBuf};

const HOME_TIMELINE_ARTIFACTS: [&str; 3] = ["run.json", "events.jsonl", "trace.jsonl"];
const HOME_ARTIFACT_COLUMN_COUNT: usize = 4;
const HOME_TOP_RISK_LIMIT: usize = 3;
const HOME_COMMANDS: [&str; 6] = [
    "target .",
    "options sast:scan",
    "tasks",
    "next",
    "quickstart",
    "Ctrl+G",
];
/// With an active engagement, `next` (continue the journey) replaces the
/// first-run `quickstart` slot.
const HOME_JOURNEY_COMMANDS: [&str; 6] = [
    "next",
    "findings",
    "options sast:scan",
    "tasks",
    "modules",
    "Ctrl+G",
];

#[derive(Debug, Clone, PartialEq)]
pub struct HomeCockpitModel {
    pub title: &'static str,
    pub attack_surface: Option<AttackSurfaceRiskModel>,
    pub next_card: HomeNextCard,
    pub findings_card: HomeFindingsCard,
    pub top_risks: Vec<HomeTopRiskRow>,
    pub run_card: HomeRunCard,
    pub workspace_line: String,
    pub command_labels: [&'static str; 6],
    /// The engagement spine (組 map → 崩 hunt → 作 confirm → 掛 fix), derived
    /// from workspace state. `None` without a target.
    pub journey: Option<JourneyModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeNextCard {
    pub action: String,
    pub mechanics: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeFindingsCard {
    pub total: usize,
    pub reviewed: usize,
    pub unreviewed: usize,
    pub counts: SeverityCounts,
    pub reviewed_counts: SeverityCounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeTopRiskRow {
    pub severity_tone: SeverityTone,
    pub severity_label: String,
    pub alias: String,
    pub rule: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRunCard {
    pub run_id: String,
    pub status: String,
    pub recorded: usize,
    pub total: usize,
    pub artifacts: Vec<HomeRunArtifactChip>,
    pub run_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeRunArtifactChip {
    pub glyph: String,
    pub label: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HomeArtifactRow {
    pub cells: [String; HOME_ARTIFACT_COLUMN_COUNT],
}

pub fn home_cockpit_model(app: &ShellApp) -> HomeCockpitModel {
    let run = HomeRunModel::from_app(app);
    let artifacts = home_artifact_rows(&run.run_dir);
    let journey = journey_model(app);
    let module_count = app.registry.modules().count();
    HomeCockpitModel {
        title: "HOME",
        attack_surface: home_attack_surface_model(&run.run_dir, &artifacts),
        next_card: home_next_card(journey.as_ref()),
        findings_card: home_findings_card(&app.findings),
        top_risks: home_top_risks(app),
        run_card: home_run_card(&run, &artifacts),
        workspace_line: home_workspace_line(app, module_count),
        command_labels: home_command_labels(journey.as_ref()),
        journey,
    }
}

fn home_command_labels(journey: Option<&JourneyModel>) -> [&'static str; 6] {
    if journey.is_some() {
        HOME_JOURNEY_COMMANDS
    } else {
        HOME_COMMANDS
    }
}

fn home_next_card(journey: Option<&JourneyModel>) -> HomeNextCard {
    journey.map_or_else(first_run_next_card, journey_next_card)
}

fn first_run_next_card() -> HomeNextCard {
    HomeNextCard {
        action: "set a target and start the guided workflow".to_string(),
        mechanics: "type `target .` or `target <path>` · then `next`".to_string(),
    }
}

fn journey_next_card(journey: &JourneyModel) -> HomeNextCard {
    HomeNextCard {
        action: journey.next_action.clone(),
        mechanics: format!("type `next` · tools: {}", journey.next_tools),
    }
}

fn home_findings_card(findings: &[Finding]) -> HomeFindingsCard {
    let reviewed = findings
        .iter()
        .filter(|finding| is_reviewed_finding(finding))
        .count();
    HomeFindingsCard {
        total: findings.len(),
        reviewed,
        unreviewed: findings.len().saturating_sub(reviewed),
        counts: SeverityCounts::from_findings(findings),
        reviewed_counts: reviewed_severity_counts(findings),
    }
}

fn reviewed_severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings
        .iter()
        .filter(|finding| is_reviewed_finding(finding))
    {
        counts.add(finding.severity);
    }
    counts
}

fn home_top_risks(app: &ShellApp) -> Vec<HomeTopRiskRow> {
    let base = target_base(app);
    cached_sorted_finding_alias_indices(app)
        .into_iter()
        .take(HOME_TOP_RISK_LIMIT)
        .filter_map(|(alias, finding_index)| {
            let finding = app.findings.get(finding_index)?;
            Some(home_top_risk_row(alias, finding, base.as_deref()))
        })
        .collect()
}

fn home_top_risk_row(alias: String, finding: &Finding, base: Option<&str>) -> HomeTopRiskRow {
    let projection = project_finding(finding, Some(alias.clone()));
    HomeTopRiskRow {
        severity_tone: SeverityTone::from_severity(projection.severity),
        severity_label: projection.severity_label,
        alias,
        rule: finding.rule_id.clone(),
        location: relativize_location(projection.location, base),
    }
}

fn home_run_card(run: &HomeRunModel, artifacts: &[HomeArtifactRow]) -> HomeRunCard {
    HomeRunCard {
        run_id: run.latest_run_label(),
        status: run_status_label(&run.run_dir),
        recorded: recorded_artifact_count(artifacts),
        total: artifacts.len(),
        artifacts: artifacts.iter().map(home_run_artifact_chip).collect(),
        run_dir: home_path_label(&run.run_dir),
    }
}

fn recorded_artifact_count(artifacts: &[HomeArtifactRow]) -> usize {
    artifacts
        .iter()
        .filter(|artifact| artifact.cells[2] == "recorded")
        .count()
}

fn home_run_artifact_chip(artifact: &HomeArtifactRow) -> HomeRunArtifactChip {
    let [glyph, label, state, _path] = &artifact.cells;
    HomeRunArtifactChip {
        glyph: glyph.clone(),
        label: label.clone(),
        state: state.clone(),
    }
}

fn home_workspace_line(app: &ShellApp, module_count: usize) -> String {
    format!(
        "target {} · modules {} · context {}",
        target_label(app),
        module_count,
        home_context_label(context_snapshot_state(app))
    )
}

fn home_context_label(state: &str) -> &'static str {
    match state {
        "present" => "built",
        "malformed" => "malformed",
        _ => "not built",
    }
}

fn target_label(app: &ShellApp) -> String {
    app.target
        .as_ref()
        .map(|path| home_path_label(path))
        .unwrap_or_else(|| "none".to_string())
}

fn home_path_label(path: &Path) -> String {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return path.display().to_string();
    };
    let Ok(rest) = path.strip_prefix(home) else {
        return path.display().to_string();
    };
    if rest.as_os_str().is_empty() {
        "~".to_string()
    } else {
        format!("~/{}", rest.display())
    }
}

fn home_attack_surface_model(
    run_dir: &Path,
    artifacts: &[HomeArtifactRow],
) -> Option<AttackSurfaceRiskModel> {
    let surface = artifacts
        .iter()
        .find(|artifact| artifact.cells[1] == "surface")?;
    matches!(surface.cells[2].as_str(), "recorded" | "partial")
        .then(|| attack_surface_risk_model(run_dir))
        .flatten()
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
        "strategy proposals" => "strategy",
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
