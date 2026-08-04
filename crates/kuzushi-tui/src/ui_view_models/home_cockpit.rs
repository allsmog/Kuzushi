use super::findings::{cached_sorted_finding_alias_indices, relativize_location, target_base};
use super::review_state::{indexed_review_decision_complete, EffectiveReviewStateIndex};
use super::{
    attack_surface_risk_model, context_snapshot_state, journey_model, ui_run_dir,
    AttackSurfaceRiskModel, JourneyModel, SeverityCounts, SeverityTone,
};
use crate::{
    app::{JsonFileState, ViewDataState},
    ShellApp,
};
use kuzushi_core::run_artifacts::{
    canonical_run_artifact_spec, canonical_run_artifact_specs, RunArtifactSpec,
};
use kuzushi_core::{
    project_finding, Finding, LatestRunPointerState, RunArtifactRead, RunArtifactTextRead,
};
use std::path::{Path, PathBuf};

const HOME_TIMELINE_ARTIFACTS: [&str; 3] = ["run.json", "items.jsonl", "events.jsonl"];
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
    /// The engagement spine (組 map → 崩 scan → 査 review → 作 prove → 掛 fix), derived
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
    let artifacts = home_artifact_rows(app, &run);
    let journey = journey_model(app);
    let module_count = app.registry().discoverable_modules().count();
    HomeCockpitModel {
        title: "HOME",
        attack_surface: attack_surface_model_for_run(app, &run),
        next_card: home_next_card(journey.as_ref()),
        findings_card: home_findings_card(app),
        top_risks: home_top_risks(app),
        run_card: home_run_card(app, &run, &artifacts),
        workspace_line: home_workspace_line(app, module_count),
        command_labels: home_command_labels(journey.as_ref()),
        journey,
    }
}

/// Project only the attack-surface artifact needed by the durable Map page.
/// This avoids constructing Home cards, finding summaries, and journey state
/// merely to obtain one already-hydrated artifact projection.
pub(crate) fn attack_surface_model(app: &ShellApp) -> Option<AttackSurfaceRiskModel> {
    attack_surface_model_for_run(app, &HomeRunModel::from_app(app))
}

fn attack_surface_model_for_run(
    app: &ShellApp,
    run: &HomeRunModel,
) -> Option<AttackSurfaceRiskModel> {
    match run_artifact_json(app, run, "attack-surface.json") {
        ViewDataState::Ready(artifact) => attack_surface_risk_model(artifact),
        ViewDataState::NotRequested | ViewDataState::Loading => None,
    }
}

/// The three deck-relevant dispositions of the already-hydrated
/// `attack-surface.json` artifact. Distinguishing a present-but-corrupt file
/// (`Malformed`/`Unreadable`/`NonFile`) from a genuinely absent one lets the
/// worklist fold degrade the former and leave the latter `Unavailable`,
/// matching the headless `worklist:rank` honesty instead of collapsing every
/// non-`Present` disposition into "no map". Read-free like
/// `attack_surface_artifact_value`: it reads the same in-memory cache entry, so
/// there is no new per-frame IO and no re-stat.
pub(crate) enum AttackSurfaceArtifactState {
    /// The artifact hydrated to a JSON value. It may still be the wrong shape;
    /// the fold decides whether it parses into a surface map.
    Present(serde_json::Value),
    /// A file backs the artifact but its bytes did not parse as JSON, could not
    /// be read, or is not a regular file. A map WAS persisted, so this is a
    /// `context:build` recovery hint, never the absent "no map" state.
    CorruptOrUnreadable,
    /// No artifact backs this engagement (absent, or not yet hydrated).
    Absent,
}

pub(crate) fn attack_surface_artifact_state(app: &ShellApp) -> AttackSurfaceArtifactState {
    match run_artifact_json(app, &HomeRunModel::from_app(app), "attack-surface.json") {
        ViewDataState::Ready(JsonFileState::Present(value)) => {
            AttackSurfaceArtifactState::Present(value)
        }
        ViewDataState::Ready(
            JsonFileState::Malformed | JsonFileState::Unreadable | JsonFileState::NonFile,
        ) => AttackSurfaceArtifactState::CorruptOrUnreadable,
        ViewDataState::Ready(JsonFileState::Missing)
        | ViewDataState::NotRequested
        | ViewDataState::Loading => AttackSurfaceArtifactState::Absent,
    }
}

/// The O(1) hydration version of the already-loaded `attack-surface.json`, or
/// `None` when it has not hydrated. Read-path memo keys (the worklist fold) key
/// on this instead of re-cloning and re-parsing the full artifact every frame.
pub(crate) fn attack_surface_artifact_version(app: &ShellApp) -> Option<u64> {
    let run = HomeRunModel::from_app(app);
    let (target, run_id) = (run.target.as_deref()?, run.run_id.as_deref()?);
    app.workbench_cache().borrow().cached_run_artifact_version(
        target,
        run_id,
        "attack-surface.json",
    )
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

fn home_findings_card(app: &ShellApp) -> HomeFindingsCard {
    let findings = app.findings();
    let review_index =
        EffectiveReviewStateIndex::from_findings_and_decisions(findings, app.review_decisions());
    let reviewed = findings
        .iter()
        .filter(|finding| indexed_review_decision_complete(&review_index, finding))
        .count();
    HomeFindingsCard {
        total: findings.len(),
        reviewed,
        unreviewed: findings.len().saturating_sub(reviewed),
        counts: SeverityCounts::from_findings(findings),
        reviewed_counts: reviewed_severity_counts(findings, &review_index),
    }
}

fn reviewed_severity_counts(
    findings: &[Finding],
    review_index: &EffectiveReviewStateIndex,
) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings
        .iter()
        .filter(|finding| indexed_review_decision_complete(review_index, finding))
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
            let finding = app.findings().get(finding_index)?;
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

fn home_run_card(app: &ShellApp, run: &HomeRunModel, artifacts: &[HomeArtifactRow]) -> HomeRunCard {
    HomeRunCard {
        run_id: run.latest_run_label(),
        status: run_status_label(app, run),
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
    app.target()
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

fn home_artifact_rows(app: &ShellApp, run: &HomeRunModel) -> Vec<HomeArtifactRow> {
    canonical_run_artifact_specs()
        .into_iter()
        .filter(home_artifact_belongs_in_rail)
        .map(|artifact| home_artifact_row(app, run, artifact))
        .collect()
}

fn home_artifact_belongs_in_rail(artifact: &RunArtifactSpec) -> bool {
    !HOME_TIMELINE_ARTIFACTS.contains(&artifact.leaf)
}

fn home_artifact_row(
    app: &ShellApp,
    run: &HomeRunModel,
    artifact: RunArtifactSpec,
) -> HomeArtifactRow {
    let read = run_artifact_text(app, run, artifact.leaf);
    let state = artifact_state(&read, &artifact);
    HomeArtifactRow {
        cells: [
            state.glyph.to_string(),
            home_artifact_label(artifact.label).to_string(),
            state.label.to_string(),
            run.run_dir.join(artifact.leaf).display().to_string(),
        ],
    }
}

fn artifact_state(
    read: &ViewDataState<RunArtifactTextRead>,
    artifact: &RunArtifactSpec,
) -> HomeArtifactState {
    let ViewDataState::Ready(read) = read else {
        return HomeArtifactState::loading();
    };
    let text = match read {
        RunArtifactRead::Ready { value, .. } => value,
        RunArtifactRead::Missing { .. } => return HomeArtifactState::missing(),
        RunArtifactRead::NonFile { .. } => return HomeArtifactState::non_file(),
        RunArtifactRead::Unsafe { .. } | RunArtifactRead::Unreadable { .. } => {
            return HomeArtifactState::malformed()
        }
    };
    if is_json_artifact(artifact) {
        return artifact_state_from_json_text(&text);
    }
    artifact_state_from_text(&text)
}

fn run_artifact_text(
    app: &ShellApp,
    run: &HomeRunModel,
    leaf: &str,
) -> ViewDataState<RunArtifactTextRead> {
    let (Some(target), Some(run_id)) = (run.target.as_deref(), run.run_id.as_deref()) else {
        return if run.hydration_pending {
            ViewDataState::Loading
        } else {
            ViewDataState::Ready(RunArtifactRead::Missing {
                path: run.run_dir.join(leaf),
            })
        };
    };
    app.workbench_cache()
        .borrow()
        .cached_run_artifact_text(target, run_id, leaf)
}

fn run_artifact_json(
    app: &ShellApp,
    run: &HomeRunModel,
    leaf: &str,
) -> ViewDataState<JsonFileState> {
    let (Some(target), Some(run_id)) = (run.target.as_deref(), run.run_id.as_deref()) else {
        return if run.hydration_pending {
            ViewDataState::Loading
        } else {
            ViewDataState::Ready(JsonFileState::Missing)
        };
    };
    app.workbench_cache()
        .borrow()
        .cached_run_artifact_json(target, run_id, leaf)
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
        "completed" => Some(HomeArtifactState::recorded()),
        "partial" => Some(HomeArtifactState::partial()),
        "failed" => Some(HomeArtifactState::failed()),
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

fn run_status_label(app: &ShellApp, run: &HomeRunModel) -> String {
    let read = run_artifact_text(app, run, run_metadata_artifact_leaf());
    let text = match read {
        ViewDataState::NotRequested | ViewDataState::Loading => {
            return "loading run metadata".to_string()
        }
        ViewDataState::Ready(read) => match read {
            RunArtifactRead::Ready { value, .. } => value,
            RunArtifactRead::Missing { .. } => return "no runs yet".to_string(),
            RunArtifactRead::NonFile { .. } => {
                return format!("{} is not a file", run_metadata_artifact_leaf())
            }
            RunArtifactRead::Unsafe { .. } | RunArtifactRead::Unreadable { .. } => {
                return malformed_run_metadata_label()
            }
        },
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
    target: Option<PathBuf>,
    run_id: Option<String>,
    latest_pointer_invalid: bool,
    hydration_pending: bool,
    run_dir: PathBuf,
}

struct HomeLatestRunState {
    run_id: Option<String>,
    invalid: bool,
    pending: bool,
}

impl HomeRunModel {
    fn from_app(app: &ShellApp) -> Self {
        let Some(root) = app.target_path_buf() else {
            return Self::without_target();
        };
        let latest = app
            .workbench_cache()
            .borrow()
            .cached_latest_run_pointer(Some(root));
        let latest = home_latest_run_state(latest);
        let run_dir = latest
            .run_id
            .as_ref()
            .map(|id| ui_run_dir(Some(root), id))
            .unwrap_or_else(|| ui_run_dir(Some(root), "latest"));
        Self {
            target: Some(root.clone()),
            run_id: latest.run_id,
            latest_pointer_invalid: latest.invalid,
            hydration_pending: latest.pending,
            run_dir,
        }
    }

    fn without_target() -> Self {
        Self {
            target: None,
            run_id: None,
            latest_pointer_invalid: false,
            hydration_pending: false,
            run_dir: ui_run_dir(None, "latest"),
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

fn home_latest_run_state(latest: ViewDataState<LatestRunPointerState>) -> HomeLatestRunState {
    let run_id = match &latest {
        ViewDataState::Ready(LatestRunPointerState::Ready(run_id)) => {
            Some(run_id.as_str().to_string())
        }
        ViewDataState::Ready(
            LatestRunPointerState::Missing | LatestRunPointerState::Invalid(_),
        )
        | ViewDataState::NotRequested
        | ViewDataState::Loading => None,
    };
    HomeLatestRunState {
        run_id,
        invalid: matches!(
            latest,
            ViewDataState::Ready(LatestRunPointerState::Invalid(_))
        ),
        pending: matches!(latest, ViewDataState::NotRequested | ViewDataState::Loading),
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

    const fn loading() -> Self {
        Self::new("…", "loading")
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
