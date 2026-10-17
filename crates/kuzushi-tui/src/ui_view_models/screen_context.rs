use super::findings::projected_visible_findings;
use crate::app::{PaneFocus, ShellView};
use crate::ShellApp;
use kuzushi_core::{
    finding_next_action, runtime_validation_summary, static_proof_summary, Finding,
    FindingEvidence, FindingNextAction, PersistedVerification,
};
use std::collections::BTreeMap;

mod model;
mod scene;
mod selection;
use selection::{finding_context_is_visible, selected_runs};

pub(crate) use model::{
    ScreenContext, ScreenCount, ScreenCursor, ScreenEvidenceContext, ScreenFindingSummary,
    ScreenProofContext, ScreenRevision, ScreenSelectedItem, ScreenTriageContext,
    ScreenVerificationContext,
};
#[cfg(test)]
pub(crate) use scene::threat_model_scene_context;
pub(crate) use scene::{
    capture_threat_model_scene_snapshot, threat_model_scene_context_from_snapshot,
    ThreatModelSceneContext, ThreatModelSceneSnapshot,
};

const VISIBLE_ROW_LIMIT: usize = 8;
const VISIBLE_ROW_TEXT_LIMIT: usize = 160;
const SCREEN_CONTEXT_LIST_LIMIT: usize = 12;
const SCREEN_CONTEXT_TEXT_LIMIT: usize = 4000;

pub(crate) fn screen_context_model(app: &ShellApp) -> ScreenContext {
    let runs = selected_runs(app);
    let selected_run = selection::single_run_label(app, &runs);
    let selected_run_count = runs.len();
    ScreenContext {
        view: shell_view_label(app),
        focused_pane: focused_pane_label(app),
        selected_item: selected_item(app),
        selected_run,
        selected_runs: runs.into_iter().take(SCREEN_CONTEXT_LIST_LIMIT).collect(),
        selected_run_count,
        selected_revision: selected_revision(app),
        active_phase: active_phase(app),
        displayed_phase: selection::displayed_phase(app),
        active_filters: active_filters(app),
        selected_scope: selected_scope(app),
        finding_summary: finding_summary(app),
        visible_rows: visible_rows(app),
        cursor: ScreenCursor {
            row: active_cursor_row(app),
            col: app.cursor(),
        },
    }
}

fn shell_view_label(app: &ShellApp) -> String {
    let view = &app.shell_view();
    core_shell_view_label(app, view)
        .or_else(|| workspace_shell_view_label(view))
        .or_else(|| system_shell_view_label(view))
        .unwrap_or("Unknown")
        .to_string()
}

fn core_shell_view_label(app: &ShellApp, view: &ShellView) -> Option<&'static str> {
    match view {
        ShellView::Home => Some("Home"),
        ShellView::Catalog => Some("Capabilities"),
        ShellView::Recommend => Some("Recommend"),
        ShellView::Module => Some("Module"),
        ShellView::ModuleRun => Some("ModuleRun"),
        ShellView::Workbench => Some("Workbench"),
        ShellView::Setup => Some(setup_screen_label(app)),
        ShellView::Report => Some("Report"),
        ShellView::Tune => Some("Tune"),
        ShellView::Threat => Some("Threat"),
        ShellView::ThreatEditor => Some("ThreatEditor"),
        ShellView::PromptsEditor => Some("PromptsEditor"),
        ShellView::ActorDetail => Some("ActorDetail"),
        ShellView::Runs => Some("Runs"),
        ShellView::Jobs => Some("Jobs"),
        ShellView::Campaign => Some("Campaign"),
        ShellView::Coverage => Some("Coverage"),
        ShellView::Relationships => Some("Relationships"),
        ShellView::Lessons => Some("Lessons"),
        ShellView::RunDiff => Some("RunDiff"),
        ShellView::Replay => Some("Replay"),
        ShellView::Trace => Some("Trace"),
        ShellView::Activity => Some("Activity"),
        _ => None,
    }
}

fn workspace_shell_view_label(view: &ShellView) -> Option<&'static str> {
    match view {
        ShellView::Context => Some("Context"),
        ShellView::ProjectModel => Some("ProjectModel"),
        ShellView::StrategyQueue => Some("StrategyQueue"),
        ShellView::Workspace => Some("Workspace"),
        ShellView::KnowledgeBase => Some("KnowledgeBase"),
        ShellView::FailureHandoff => Some("FailureHandoff"),
        ShellView::History => Some("History"),
        ShellView::Story => Some("Story"),
        ShellView::Patch => Some("Patch"),
        ShellView::Pwn => Some("Pwn"),
        ShellView::Scene => Some("Scene"),
        _ => None,
    }
}

fn system_shell_view_label(view: &ShellView) -> Option<&'static str> {
    match view {
        ShellView::Help => Some("Help"),
        ShellView::Quickstart => Some("Quickstart"),
        ShellView::Logs => Some("Logs"),
        ShellView::Config => Some("Config"),
        ShellView::Permissions => Some("Permissions"),
        ShellView::Health => Some("Health"),
        ShellView::Tools => Some("Tools"),
        ShellView::Options => Some("Options"),
        ShellView::SastTasks => Some("SastTasks"),
        ShellView::Auth => Some("Auth"),
        ShellView::Cost => Some("Cost"),
        ShellView::BootSplash => Some("BootSplash"),
        ShellView::QuitConfirm => Some("QuitConfirm"),
        ShellView::ConfirmDialog => Some("ConfirmDialog"),
        ShellView::ThemePicker => Some("ThemePicker"),
        ShellView::Keymap => Some("Keymap"),
        ShellView::UpdateAvailable => Some("UpdateAvailable"),
        ShellView::Interruption => Some("Interruption"),
        ShellView::CommandPalette => Some("CommandPalette"),
        ShellView::TargetPicker => Some("TargetPicker"),
        ShellView::PlanningPicker => Some("PlanningPicker"),
        _ => None,
    }
}

fn setup_screen_label(app: &ShellApp) -> &'static str {
    match app.router.setup().editor() {
        Some(crate::app::SetupEditor::Details) => "SetupDetails",
        Some(crate::app::SetupEditor::Model) => "SetupModel",
        Some(crate::app::SetupEditor::Credentials) => "SetupCredentials",
        Some(crate::app::SetupEditor::Plan) => "SetupMapPlan",
        Some(crate::app::SetupEditor::ThreatModel) => "SetupThreatModel",
        Some(crate::app::SetupEditor::Prompt) => "SetupPrompt",
        Some(crate::app::SetupEditor::Budget) => "SetupBudget",
        Some(crate::app::SetupEditor::Target) => "SetupTarget",
        None => "Setup",
    }
}

fn focused_pane_label(app: &ShellApp) -> Option<String> {
    match app.shell_view() {
        ShellView::Workbench => {
            workbench_phase_plan(app).map(|plan| plan.effective_focus.label().to_string())
        }
        ShellView::Activity => app.activity().map(|activity| {
            pane_focus_label(app.activity_route().effective_pane_focus(activity)).to_string()
        }),
        _ => None,
    }
}

fn workbench_phase_plan(app: &ShellApp) -> Option<super::PhasePresentationPlan> {
    let viewport = app.viewport();
    crate::renderer::workbench_phase_plan_for_app(
        app,
        ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows),
    )
}

fn pane_focus_label(pane: PaneFocus) -> &'static str {
    match pane {
        PaneFocus::Left => "Dag",
        PaneFocus::Right => "Output",
    }
}

fn selected_item(app: &ShellApp) -> Option<ScreenSelectedItem> {
    if !finding_context_is_visible(app) {
        return None;
    }
    let (alias, finding) = super::current_finding_for_detail(app)?;
    Some(selected_item_from_finding(&finding, alias))
}

fn selected_item_from_finding(finding: &Finding, alias: Option<String>) -> ScreenSelectedItem {
    ScreenSelectedItem {
        alias: alias.clone(),
        fingerprint: finding.fingerprint.clone(),
        title: finding.title.clone(),
        file: finding.file_path.clone(),
        line: finding.start_line,
        rank: finding.severity.as_str().to_string(),
        state: classification_state(finding),
        runtime_verification: runtime_verification_state(finding),
        triage: triage_context(finding),
        proof: proof_context(finding, alias.as_deref()),
        evidence: evidence_context(finding),
    }
}

fn triage_context(finding: &Finding) -> Option<ScreenTriageContext> {
    finding.triage.as_ref().map(|triage| ScreenTriageContext {
        verdict: triage.verdict.as_str().to_string(),
        confidence: format!("{:.2}", triage.confidence),
        rationale: bounded_prompt_text(&triage.rationale),
    })
}

fn proof_context(finding: &Finding, alias: Option<&str>) -> ScreenProofContext {
    let static_proof = static_proof_summary(finding.static_proof_state);
    let runtime = runtime_validation_summary(finding.verification.as_ref());
    let next_action = finding_next_action(finding, None);
    ScreenProofContext {
        static_label: static_proof.label.to_string(),
        static_explanation: static_proof.explanation.to_string(),
        runtime_label: runtime.label,
        runtime_explanation: runtime.explanation.to_string(),
        verification: finding.verification.as_ref().map(verification_context),
        next_action: next_action.as_str().to_string(),
        next_command: next_action_command(next_action, alias),
        next_detail: next_action_detail(next_action).to_string(),
    }
}

fn verification_context(verification: &PersistedVerification) -> ScreenVerificationContext {
    ScreenVerificationContext {
        verdict: verification.proof_verdict.as_str().to_string(),
        proof_level: verification.proof_level,
        backend: verification.backend.as_str().to_string(),
        language: verification.language.clone(),
        harness: verification
            .harness_path
            .as_ref()
            .map(|path| bounded_prompt_text(path)),
        crash_evidence: verification
            .crash_evidence
            .as_ref()
            .map(|evidence| bounded_prompt_text(evidence)),
        notes: bounded_prompt_list(&verification.notes),
    }
}

fn next_action_command(action: FindingNextAction, alias: Option<&str>) -> Option<String> {
    let alias = alias.unwrap_or("selected");
    match action {
        FindingNextAction::Validate => Some(format!("verify {alias}")),
        FindingNextAction::Patch => Some(format!("patch {alias}")),
        FindingNextAction::Suppress | FindingNextAction::Review => None,
    }
}

fn next_action_detail(action: FindingNextAction) -> &'static str {
    match action {
        FindingNextAction::Validate => {
            "collect runtime proof or stronger source evidence before patching"
        }
        FindingNextAction::Patch => "runtime proof is recorded; generate remediation",
        FindingNextAction::Suppress => "review the rejection evidence before suppressing",
        FindingNextAction::Review => "review the finding and keep evidence attached",
    }
}

fn evidence_context(finding: &Finding) -> Vec<ScreenEvidenceContext> {
    finding
        .evidence
        .iter()
        .take(SCREEN_CONTEXT_LIST_LIMIT)
        .map(evidence_item_context)
        .collect()
}

fn evidence_item_context(evidence: &FindingEvidence) -> ScreenEvidenceContext {
    ScreenEvidenceContext {
        kind: evidence.kind.clone(),
        file: evidence.file_path.clone(),
        line: evidence.line,
        confidence: evidence.confidence,
        snippet: bounded_prompt_text(&evidence.snippet),
        rationale: bounded_prompt_text(&evidence.rationale),
    }
}

fn classification_state(finding: &Finding) -> String {
    finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str().to_string())
        .unwrap_or_else(|| "untriaged".to_string())
}

fn runtime_verification_state(finding: &Finding) -> String {
    finding
        .verification
        .as_ref()
        .map(|verification| {
            if verification.is_model_assessment() {
                "model_assessed".to_string()
            } else {
                verification.proof_verdict.as_str().to_string()
            }
        })
        .unwrap_or_else(|| "not_verified".to_string())
}

fn selected_revision(app: &ShellApp) -> Option<ScreenRevision> {
    // Report names recorded source in its body. Checkout metadata is not its source identity.
    if app.shell_view() == ShellView::Report {
        return None;
    }
    match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(app.target())
    {
        crate::app::ViewDataState::Ready(Some(git)) => Some(ScreenRevision::from(git)),
        crate::app::ViewDataState::Ready(None)
        | crate::app::ViewDataState::NotRequested
        | crate::app::ViewDataState::Loading => None,
    }
}

fn active_phase(app: &ShellApp) -> Option<String> {
    if !super::journey::investigation_chrome_is_visible(app) {
        return None;
    }
    super::journey_model(app).map(|journey| {
        crate::app::WorkbenchPage::from_phase(journey.current)
            .title()
            .to_ascii_lowercase()
    })
}

fn active_filters(app: &ShellApp) -> Vec<String> {
    match &app.shell_view() {
        ShellView::Options => vec![format!("options:{}", app.router.options().filter.label())],
        _ => Vec::new(),
    }
}

fn selected_scope(app: &ShellApp) -> Option<String> {
    super::active_project_scope_label(app).or_else(|| {
        app.target()
            .map(|path| super::compact_target_path(&path.to_string_lossy()))
    })
}

fn finding_summary(app: &ShellApp) -> Option<ScreenFindingSummary> {
    if !finding_context_is_visible(app) || app.findings().is_empty() {
        return None;
    }
    let findings = projected_visible_findings(app)
        .iter()
        .map(|projected| projected.finding.clone())
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return None;
    }
    Some(ScreenFindingSummary {
        total: findings.len(),
        by_severity: count_findings(&findings, severity_bucket),
        by_verdict: count_findings(&findings, classification_state),
        by_proof_state: count_findings(&findings, proof_state_bucket),
        runtime_proof_by_severity: count_findings(
            runtime_proven_findings(&findings),
            severity_bucket,
        ),
    })
}

fn runtime_proven_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|finding| {
            finding
                .verification
                .as_ref()
                .is_some_and(PersistedVerification::is_empirically_verified)
        })
        .collect()
}

fn count_findings<'a, I, F>(findings: I, label_for: F) -> Vec<ScreenCount>
where
    I: IntoIterator<Item = &'a Finding>,
    F: Fn(&Finding) -> String,
{
    let mut counts = BTreeMap::<String, usize>::new();
    for finding in findings {
        *counts.entry(label_for(finding)).or_default() += 1;
    }
    counts
        .into_iter()
        .take(SCREEN_CONTEXT_LIST_LIMIT)
        .map(|(label, count)| ScreenCount { label, count })
        .collect()
}

fn severity_bucket(finding: &Finding) -> String {
    finding.severity.as_str().to_string()
}

fn proof_state_bucket(finding: &Finding) -> String {
    finding
        .verification
        .as_ref()
        .map(|verification| {
            if verification.is_model_assessment() {
                "model_assessed".to_string()
            } else {
                verification.proof_verdict.as_str().to_string()
            }
        })
        .or_else(|| {
            finding
                .static_proof_state
                .map(|state| state.as_str().to_string())
        })
        .unwrap_or_else(|| "not_verified".to_string())
}

fn visible_rows(app: &ShellApp) -> Vec<String> {
    match app.shell_view() {
        ShellView::Runs => visible_run_rows(app),
        ShellView::RunDiff => visible_run_diff_rows(
            app,
            app.router.run_diff().left(),
            app.router.run_diff().right(),
        ),
        ShellView::Activity => visible_activity_rows(app),
        ShellView::StrategyQueue => visible_strategy_rows(app),
        _ => visible_rows_for_finding_context(app),
    }
}

fn visible_rows_for_finding_context(app: &ShellApp) -> Vec<String> {
    if finding_context_is_visible(app) {
        return visible_finding_rows(app);
    }
    Vec::new()
}

fn visible_finding_rows(app: &ShellApp) -> Vec<String> {
    super::findings_model(app)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| {
            bounded_row(format!(
                "{} {} {} {} {} {} {}",
                row.alias,
                row.severity_label,
                row.verdict,
                row.run_label,
                row.revision_label,
                row.title,
                row.location
            ))
        })
        .collect()
}

fn visible_run_rows(app: &ShellApp) -> Vec<String> {
    super::run_timeline_model(app, VISIBLE_ROW_LIMIT)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| bounded_row(row.cells.join(" ")))
        .collect()
}

fn visible_run_diff_rows(app: &ShellApp, left: &str, right: &str) -> Vec<String> {
    let model = super::run_diff_model(app, left, right);
    model
        .new_findings
        .iter()
        .map(|row| format!("new {} {} {}", row.state.severity, row.title, row.location))
        .chain(model.changed_findings.iter().map(|row| {
            format!(
                "changed {}->{} {} {}",
                row.before.severity, row.after.severity, row.title, row.location
            )
        }))
        .chain(model.uncertain_matches.iter().map(|row| {
            format!(
                "uncertain_match {}->{} {} {} -> {}",
                row.before.severity,
                row.after.severity,
                row.title,
                row.left_location,
                row.right_location
            )
        }))
        .chain(model.not_seen.iter().map(|row| {
            format!(
                "not_seen {} {} {}",
                row.state.severity, row.title, row.location
            )
        }))
        .take(VISIBLE_ROW_LIMIT)
        .map(bounded_row)
        .collect()
}

fn visible_activity_rows(app: &ShellApp) -> Vec<String> {
    app.activity()
        .map(|activity| {
            let presentation =
                kuzushi_core::run_lifecycle::present_projection_with_hydration_and_health(
                    &activity.run_projection,
                    kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1,
                    &activity.run_presentation_hydration,
                    activity.effective_run_lifecycle_health(),
                );
            presentation
                .timeline_text_rows()
                .into_iter()
                .rev()
                .take(VISIBLE_ROW_LIMIT)
                .map(|row| bounded_row(row.text))
                .collect()
        })
        .unwrap_or_default()
}

fn visible_strategy_rows(app: &ShellApp) -> Vec<String> {
    super::strategy_queue_model(app)
        .rows
        .iter()
        .take(VISIBLE_ROW_LIMIT)
        .map(|row| {
            bounded_row(format!(
                "{} {} {}",
                row.cells.join(" "),
                row.lineage,
                row.rationale
            ))
        })
        .collect()
}

fn bounded_row(value: String) -> String {
    if value.chars().count() <= VISIBLE_ROW_TEXT_LIMIT {
        return value;
    }
    format!(
        "{}...",
        value
            .chars()
            .take(VISIBLE_ROW_TEXT_LIMIT)
            .collect::<String>()
    )
}

fn bounded_prompt_text(text: &str) -> String {
    if text.chars().count() <= SCREEN_CONTEXT_TEXT_LIMIT {
        return text.to_string();
    }
    format!(
        "{}...",
        text.chars()
            .take(SCREEN_CONTEXT_TEXT_LIMIT)
            .collect::<String>()
    )
}

fn bounded_prompt_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .take(SCREEN_CONTEXT_LIST_LIMIT)
        .map(|value| bounded_prompt_text(value))
        .collect()
}

fn active_cursor_row(app: &ShellApp) -> usize {
    match app.shell_view() {
        ShellView::Workbench => workbench_phase_plan(app)
            .and_then(|plan| plan.surface(plan.effective_focus).copied())
            .map(|surface| match surface.interaction {
                super::SurfaceInteraction::Selectable => app.router.findings().cursor(),
                super::SurfaceInteraction::Scrollable => {
                    app.router.workbench().scroll().get(surface.id) as usize
                }
                super::SurfaceInteraction::Static | super::SurfaceInteraction::Diagram => 0,
            })
            .unwrap_or_default(),
        ShellView::Runs => app.router.default_scroll().offset() as usize,
        ShellView::Activity => app
            .activity()
            .map(
                |activity| match app.activity_route().effective_pane_focus(activity) {
                    PaneFocus::Left => app.activity_route().task_scroll,
                    PaneFocus::Right => app.activity_route().feed_scroll,
                },
            )
            .unwrap_or_default(),
        _ => app.router.default_scroll().offset() as usize,
    }
}

trait OptionsFilterLabel {
    fn label(self) -> &'static str;
}

impl OptionsFilterLabel for crate::app::OptionsFilter {
    fn label(self) -> &'static str {
        match self {
            crate::app::OptionsFilter::Standard => "standard",
            crate::app::OptionsFilter::Advanced => "advanced",
            crate::app::OptionsFilter::Missing => "missing",
        }
    }
}

#[cfg(test)]
mod tests;
