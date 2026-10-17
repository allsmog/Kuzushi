//! View models for the canonical phase-native Workbench chrome.

use super::phase_cockpit::phase_cockpit_model_for_phase_with_journey;
use super::{
    journey_model, journey_phase_segment, journey_reality_projection, threat_model_doc,
    FindingDetailModel, JourneyModel, JourneyPhaseStatus, PhaseCockpitModel, PhaseSurfaceId,
    ReviewQueueMode,
};
use crate::app::{WorkbenchPage, WorkflowPhase};
use crate::ShellApp;
use kuzushi_core::findings::FindingReviewCompletenessFilter;
use kuzushi_core::FindingListFilter;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkbenchState {
    FirstRun,
    Scanning,
    Review,
    FindingDetail,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchTopBar {
    pub(crate) brand: &'static str,
    pub(crate) project: String,
    pub(crate) target: String,
    pub(crate) liveness: WorkLiveness,
    pub(crate) phase: Option<String>,
    pub(crate) page: WorkbenchPage,
    pub(crate) phase_rail: Vec<JourneyPhaseStatus>,
    pub(crate) phase_next_summary: Option<String>,
}

/// Truthful activity badge state. `Idle` means nothing is changing the
/// workspace — neither local workers nor external writers. An external
/// writer flooding `.kuzushi` state must surface as `ExternalSync`, not
/// masquerade as idle while the watcher churns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkLiveness {
    Live,
    ExternalSync,
    Idle,
}

/// How long the external-sync badge lingers after the last watcher batch.
/// Long enough to survive the once-per-second liveness redraw, short enough
/// to decay promptly once the external writer goes quiet.
const EXTERNAL_SYNC_BADGE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

pub(crate) fn work_liveness(app: &ShellApp) -> WorkLiveness {
    if app.has_running_work() || app.review_decision_write_pending() {
        WorkLiveness::Live
    } else if app.ui().recent_external_sync(EXTERNAL_SYNC_BADGE_WINDOW) {
        WorkLiveness::ExternalSync
    } else {
        WorkLiveness::Idle
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchHint {
    pub(crate) verb: Cow<'static, str>,
    pub(crate) label: Cow<'static, str>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchChromeModel {
    pub(crate) page: WorkbenchPage,
    pub(crate) top_bar: WorkbenchTopBar,
    pub(crate) command_bar_hints: Vec<WorkbenchHint>,
    pub(crate) zoom: Option<PhaseSurfaceId>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchPresentationSnapshot {
    pub(crate) page: WorkbenchPage,
    pub(crate) phase: PhaseCockpitModel,
    pub(crate) chrome: WorkbenchChromeModel,
}

pub(crate) const WORKBENCH_REPORT_COMMAND: &str = "report";
const WORKBENCH_REVERIFY_ACTION_KEY: &str = "v";

static PROVE_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    hint("v", "verify displayed"),
    hint("x", "suppress displayed"),
    hint("z", "attack path / replay"),
    hint("findings", "reveal queue"),
];

const MAP_GALLERY_CYCLE_VERB: &str = "Tab";
const MAP_GALLERY_ZOOM_VERB: &str = "z";

static MAP_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    hint(MAP_GALLERY_CYCLE_VERB, "cycle map views"),
    hint(MAP_GALLERY_ZOOM_VERB, "zoom selected view"),
    hint("next", "continue to Scan"),
    hint("jobs", "inspect Map runs"),
];

static SCAN_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    hint("run sast:scan {}", "scan now"),
    hint("next", "continue workspace phase"),
    hint("z", "open findings heatmap"),
    hint("jobs", "inspect run receipts"),
];

static REVIEW_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    hint("B", "review decision backlog"),
    hint("Enter", "finding details"),
    hint("findings", "full queue"),
    hint("z", "open heatmap"),
];

static FIX_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    hint("run patch:finding", "patch displayed"),
    hint(WORKBENCH_REVERIFY_ACTION_KEY, "reverify applied patch"),
    hint("z", "chain / DFD"),
    hint("report", "open Report"),
];

const REPORT_HINT: WorkbenchHint = WorkbenchHint {
    verb: Cow::Borrowed("report"),
    label: Cow::Borrowed("open Report"),
};

/// A hint that sends the operator to Review. The verb is derived from the
/// page keymap rather than written out, so it always names the digit that
/// actually reaches Review.
fn review_page_hint(label: &'static str) -> WorkbenchHint {
    WorkbenchHint {
        verb: Cow::Owned(WorkbenchPage::Review.page_key().to_string()),
        label: Cow::Borrowed(label),
    }
}

/// What the command bar knows about the page's selected finding.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SelectedFindingHints<'a> {
    pub(crate) has_detail: bool,
    /// Operator reference (alias, else fingerprint) of the selected finding.
    pub(crate) reference: Option<&'a str>,
    /// Fix only: the selected finding has no patch draft or remediation
    /// record yet, so `patch <alias>` drafts one rather than redoing one.
    pub(crate) awaiting_patch_draft: bool,
}

const fn hint(verb: &'static str, label: &'static str) -> WorkbenchHint {
    WorkbenchHint {
        verb: Cow::Borrowed(verb),
        label: Cow::Borrowed(label),
    }
}

fn workbench_chrome_model_with_journey(
    app: &ShellApp,
    page: WorkbenchPage,
    phase: &PhaseCockpitModel,
    journey: Option<&JourneyModel>,
) -> WorkbenchChromeModel {
    let detail = phase.selected_finding_detail();
    let reference = detail.map(finding_operator_reference);
    let selection = SelectedFindingHints {
        has_detail: detail.is_some(),
        reference: reference.as_deref(),
        awaiting_patch_draft: phase.selected_finding_awaits_patch_draft(),
    };
    workbench_chrome_model_for_selection_with_journey(app, page, selection, journey)
}

/// Operator surfaces speak in aliases (`F-0001`); the raw fingerprint is
/// only a fallback for a finding the ledger has not aliased yet.
fn finding_operator_reference(detail: &FindingDetailModel) -> String {
    detail
        .alias
        .clone()
        .unwrap_or_else(|| detail.fingerprint.clone())
}

fn workbench_chrome_model_for_selection_with_journey(
    app: &ShellApp,
    page: WorkbenchPage,
    selection: SelectedFindingHints<'_>,
    journey: Option<&JourneyModel>,
) -> WorkbenchChromeModel {
    let state = workbench_state(app, journey);
    let mode = active_review_queue_mode(app);
    let report_cta = report_cta(state, super::visible_findings_len(app), mode);
    chrome_model(app, page, report_cta, selection, journey)
}

fn chrome_model(
    app: &ShellApp,
    page: WorkbenchPage,
    report_cta: Option<WorkbenchHint>,
    selection: SelectedFindingHints<'_>,
    journey: Option<&JourneyModel>,
) -> WorkbenchChromeModel {
    WorkbenchChromeModel {
        page,
        top_bar: top_bar_model(app, page, journey),
        command_bar_hints: command_bar_hints(app, page, report_cta, selection),
        zoom: app.router.workbench().zoom().surface(),
    }
}

pub(crate) fn active_review_queue_mode(app: &ShellApp) -> ReviewQueueMode {
    let Some(expression) = app.active_findings_filter().as_deref() else {
        return ReviewQueueMode::All;
    };
    let Ok(filter) = FindingListFilter::from_filter_expression(expression) else {
        return ReviewQueueMode::All;
    };
    review_queue_mode_for_completeness(&filter.completeness)
}

pub(crate) fn workbench_report_command(_mode: ReviewQueueMode) -> Cow<'static, str> {
    Cow::Borrowed(WORKBENCH_REPORT_COMMAND)
}

fn review_queue_mode_for_completeness(
    completeness: &[FindingReviewCompletenessFilter],
) -> ReviewQueueMode {
    match completeness {
        [FindingReviewCompletenessFilter::Open] => ReviewQueueMode::Open,
        [FindingReviewCompletenessFilter::Complete] => ReviewQueueMode::Complete,
        _ => ReviewQueueMode::All,
    }
}

pub(crate) fn active_workbench_page(app: &ShellApp) -> WorkbenchPage {
    active_workbench_page_with_phase_builder(app, |app| {
        journey_reality_projection(app).map(|reality| reality.current)
    })
}

fn active_workbench_page_with_phase_builder<F>(app: &ShellApp, build_phase: F) -> WorkbenchPage
where
    F: FnOnce(&ShellApp) -> Option<WorkflowPhase>,
{
    immediate_workbench_page(app)
        .or_else(|| build_phase(app).map(WorkbenchPage::from_phase))
        .unwrap_or(WorkbenchPage::Review)
}

pub(crate) fn active_workbench_page_with_journey(
    app: &ShellApp,
    journey: Option<&JourneyModel>,
) -> WorkbenchPage {
    active_workbench_page_with_reality_phase(app, journey.map(|journey| journey.current))
}

pub(crate) fn active_workbench_page_with_reality_phase(
    app: &ShellApp,
    reality_phase: Option<WorkflowPhase>,
) -> WorkbenchPage {
    immediate_workbench_page(app)
        .or_else(|| reality_phase.map(WorkbenchPage::from_phase))
        .unwrap_or(WorkbenchPage::Review)
}

fn immediate_workbench_page(app: &ShellApp) -> Option<WorkbenchPage> {
    app.router
        .workbench()
        .page()
        .or_else(|| unresolved_result_page(app))
}

/// While a phase attempt is unresolved (RESULT READY), the workbench stays
/// anchored to that phase's page: the advertised resolution keys, pane
/// cycling, and hints must all describe the result the operator is being
/// asked to resolve, not a page re-derived from refreshed reality.
fn unresolved_result_page(app: &ShellApp) -> Option<WorkbenchPage> {
    kuzushi_core::WorkflowPhase::INVESTIGATION_ORDER
        .iter()
        .copied()
        .find(|phase| app.engagement.unresolved_phase_attempt(*phase).is_some())
        .map(WorkbenchPage::from_phase)
}

pub(crate) fn workbench_presentation_snapshot(app: &ShellApp) -> WorkbenchPresentationSnapshot {
    build_workbench_presentation_snapshot(app, journey_model)
}

fn build_workbench_presentation_snapshot<F>(
    app: &ShellApp,
    build_journey: F,
) -> WorkbenchPresentationSnapshot
where
    F: FnOnce(&ShellApp) -> Option<JourneyModel>,
{
    let journey = build_journey(app);
    let page = active_workbench_page_with_journey(app, journey.as_ref());
    let phase = phase_cockpit_model_for_phase_with_journey(app, page.phase(), journey.as_ref());
    let chrome = workbench_chrome_model_with_journey(app, page, &phase, journey.as_ref());
    WorkbenchPresentationSnapshot {
        page,
        phase,
        chrome,
    }
}

fn command_bar_hints(
    app: &ShellApp,
    page: WorkbenchPage,
    report_cta: Option<WorkbenchHint>,
    selection: SelectedFindingHints<'_>,
) -> Vec<WorkbenchHint> {
    let mut hints = page_command_bar_hints(app, page);
    customize_phase_hints(&mut hints, app, page, selection);
    qualify_map_zoom_hint(&mut hints, app, page);
    if page == WorkbenchPage::Prove && !selection.has_detail {
        hints[0] = review_page_hint("choose a finding in Review");
    }
    append_report_hint(&mut hints, report_cta);
    append_phase_planner_hint(&mut hints, app, page);
    hints
}

fn qualify_map_zoom_hint(hints: &mut [WorkbenchHint], app: &ShellApp, page: WorkbenchPage) {
    if page != WorkbenchPage::Map {
        return;
    }
    if let Some(hint) = hints.iter_mut().find(|hint| hint.verb == "z") {
        hint.verb = Cow::Owned(workbench_navigate_control_hint(app, "z"));
    }
}

/// A completed or passed phase's verb opens this page, so the page itself
/// names the explicit way back into its planner. It is appended last so a
/// narrow hint row drops it before the page's own actions or Report.
fn append_phase_planner_hint(hints: &mut Vec<WorkbenchHint>, app: &ShellApp, page: WorkbenchPage) {
    let phase = page.phase();
    if !super::phase_verb_opens_page(app, phase) {
        return;
    }
    hints.push(WorkbenchHint {
        verb: Cow::Owned(format!("plan {}", phase.word())),
        label: Cow::Owned(format!("open {} planner", phase.title())),
    });
}

fn customize_phase_hints(
    hints: &mut [WorkbenchHint],
    app: &ShellApp,
    page: WorkbenchPage,
    selection: SelectedFindingHints<'_>,
) {
    match page {
        WorkbenchPage::Fix if app.engagement.pending_patch().is_some() => {
            expose_pending_patch_actions(hints);
        }
        WorkbenchPage::Fix => {
            replace_patch_hint(hints, selection);
            replace_reverify_hint(hints, app);
        }
        WorkbenchPage::Review => replace_review_decision_hint(hints, app),
        WorkbenchPage::Map | WorkbenchPage::Scan => replace_next_destination_hint(hints, app),
        WorkbenchPage::Prove => {}
    }
}

/// Item 4a: `next` runs the LEDGER-derived planner, which may not match the
/// page on screen. The hint names the real destination so its label always
/// agrees with what Enter would actually run.
fn replace_next_destination_hint(hints: &mut [WorkbenchHint], app: &ShellApp) {
    let Some(journey) = super::journey::journey_model(app) else {
        return;
    };
    let Some(hint) = hints.iter_mut().find(|hint| hint.verb == "next") else {
        return;
    };
    let destination = journey
        .next_summary
        .split(" · ")
        .next()
        .unwrap_or(journey.next_summary.as_str())
        .to_string();
    hint.label = Cow::Owned(format!("→ {destination}"));
}

pub(crate) fn workbench_reverify_control_hint(app: &ShellApp) -> String {
    workbench_navigate_control_hint(app, WORKBENCH_REVERIFY_ACTION_KEY)
}

fn workbench_navigate_control_hint(app: &ShellApp, action_key: &str) -> String {
    if app.input_mode() == crate::InputMode::Navigate {
        return action_key.to_string();
    }
    let bindings = app
        .ui()
        .keymap_binding_labels("composer", "navigate_mode", &["Esc"]);
    if bindings.is_empty() {
        return "Navigate unbound".to_string();
    }
    let prefix = (!app.input().is_empty()).then_some("clear prompt then ");
    format!(
        "{}{bindings} then {action_key}",
        prefix.unwrap_or_default(),
        bindings = bindings.join("/")
    )
}

fn replace_reverify_hint(hints: &mut [WorkbenchHint], app: &ShellApp) {
    let Some(hint) = hints
        .iter_mut()
        .find(|hint| hint.label == "reverify applied patch")
    else {
        return;
    };
    hint.verb = Cow::Owned(workbench_reverify_control_hint(app));
}

fn replace_review_decision_hint(hints: &mut [WorkbenchHint], app: &ShellApp) {
    let Some(hint) = hints
        .iter_mut()
        .find(|hint| hint.label == "review decision backlog")
    else {
        return;
    };
    hint.verb = Cow::Owned(workbench_navigate_control_hint(app, "B"));
    if super::review_backlog_active(app) {
        hint.label = Cow::Borrowed("backlog off; t tool filter; T trace");
    }
}

fn expose_pending_patch_actions(hints: &mut [WorkbenchHint]) {
    let replacements = [
        hint("patch apply", "write reviewed diff"),
        hint("patch reject", "discard candidate"),
        hint("patch regen", "replace candidate"),
    ];
    for (slot, replacement) in hints.iter_mut().zip(replacements) {
        *slot = replacement;
    }
}

fn append_report_hint(hints: &mut Vec<WorkbenchHint>, report_cta: Option<WorkbenchHint>) {
    let Some(report_cta) = report_cta else {
        return;
    };
    if !hints.iter().any(|hint| hint.verb == report_cta.verb) {
        hints.push(report_cta);
    }
}

/// `patch <alias>` works from any page. When the selected finding has no
/// draft yet the hint says so, since the review-gated journey may not have
/// reached Fix.
fn replace_patch_hint(hints: &mut [WorkbenchHint], selection: SelectedFindingHints<'_>) {
    let Some(reference) = selection.reference else {
        return;
    };
    let Some(hint) = hints
        .iter_mut()
        .find(|hint| hint.label == "patch displayed")
    else {
        return;
    };
    hint.verb = Cow::Owned(format!("patch {reference}"));
    if selection.awaiting_patch_draft {
        hint.label = Cow::Borrowed("draft a patch");
    }
}

/// `Tab` cycles the Map projection, and `z` zooms the selected projection,
/// only while Map has a gallery body. This row is a header row, so the body
/// area the composition solves is sized from it and it cannot ask which
/// composition won; it names only what a ready Map guarantees at every
/// terminal size. Where the gallery is the canvas of an action-required Map
/// its own header advertises those keys — this row stays silent about them
/// rather than naming a key that a Map with only its readiness card would
/// refuse. There `z` opens the Map viz deck, which is what the Navigate
/// footer and the keymap already say. The remaining Map hints stay true in
/// both states.
fn page_command_bar_hints(app: &ShellApp, page: WorkbenchPage) -> Vec<WorkbenchHint> {
    if page == WorkbenchPage::Review {
        return review_command_bar_hints(!app.findings().is_empty());
    }
    let hints = page_command_bar_hint_slice(page).to_vec();
    if page != WorkbenchPage::Map || super::ready_map_gallery_is_primary(app) {
        return hints;
    }
    hints
        .into_iter()
        .filter(|hint| hint.verb != MAP_GALLERY_CYCLE_VERB)
        .map(map_hint_without_gallery)
        .collect()
}

fn review_command_bar_hints(has_findings: bool) -> Vec<WorkbenchHint> {
    REVIEW_COMMAND_BAR_HINTS
        .iter()
        .filter(|hint| has_findings || hint.verb != "z")
        .cloned()
        .collect()
}

fn map_hint_without_gallery(hint: WorkbenchHint) -> WorkbenchHint {
    if hint.verb != MAP_GALLERY_ZOOM_VERB {
        return hint;
    }
    WorkbenchHint {
        verb: hint.verb,
        label: Cow::Borrowed("open map viz"),
    }
}

fn page_command_bar_hint_slice(page: WorkbenchPage) -> &'static [WorkbenchHint] {
    match page {
        WorkbenchPage::Map => &MAP_COMMAND_BAR_HINTS,
        WorkbenchPage::Scan => &SCAN_COMMAND_BAR_HINTS,
        WorkbenchPage::Review => &REVIEW_COMMAND_BAR_HINTS,
        WorkbenchPage::Prove => &PROVE_COMMAND_BAR_HINTS,
        WorkbenchPage::Fix => &FIX_COMMAND_BAR_HINTS,
    }
}

fn report_cta(
    state: WorkbenchState,
    finding_total: usize,
    _mode: ReviewQueueMode,
) -> Option<WorkbenchHint> {
    (state == WorkbenchState::Report || finding_total > 0).then_some(REPORT_HINT)
}

fn top_bar_model(
    app: &ShellApp,
    page: WorkbenchPage,
    journey: Option<&JourneyModel>,
) -> WorkbenchTopBar {
    WorkbenchTopBar {
        brand: "Kuzushi",
        project: project_label(app),
        target: target_label(app),
        liveness: work_liveness(app),
        phase: journey.map(|journey| journey_phase_segment(journey.current)),
        page,
        phase_rail: journey
            .map(|journey| journey.phases.clone())
            .unwrap_or_default(),
        phase_next_summary: journey.map(|journey| journey.next_summary.clone()),
    }
}

fn project_label(app: &ShellApp) -> String {
    if app.target().is_some() {
        super::scoped_target_path_label(app)
    } else {
        "no target".to_string()
    }
}

fn target_label(app: &ShellApp) -> String {
    app.focused_module_owned()
        .unwrap_or_else(|| "all modules".to_string())
}

fn workbench_state(app: &ShellApp, journey: Option<&JourneyModel>) -> WorkbenchState {
    derive_state(WorkbenchStateInputs {
        scanning: app.has_running_work(),
        selected: app.selected_finding().is_some(),
        has_findings: !app.findings().is_empty(),
        has_threat_doc: threat_model_doc(app).is_some(),
        at_fix: journey.is_some_and(|journey| journey.current == WorkflowPhase::Fix),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkbenchStateInputs {
    scanning: bool,
    selected: bool,
    has_findings: bool,
    has_threat_doc: bool,
    at_fix: bool,
}

impl WorkbenchStateInputs {
    fn is_first_run(self) -> bool {
        !self.has_findings && !self.has_threat_doc
    }

    fn scanning_state(self) -> Option<WorkbenchState> {
        self.scanning.then_some(WorkbenchState::Scanning)
    }

    fn finding_detail_state(self) -> Option<WorkbenchState> {
        self.selected.then_some(WorkbenchState::FindingDetail)
    }

    fn first_run_state(self) -> Option<WorkbenchState> {
        self.is_first_run().then_some(WorkbenchState::FirstRun)
    }

    fn report_state(self) -> Option<WorkbenchState> {
        self.at_fix.then_some(WorkbenchState::Report)
    }
}

fn derive_state(inputs: WorkbenchStateInputs) -> WorkbenchState {
    inputs
        .scanning_state()
        .or(inputs.finding_detail_state())
        .or(inputs.first_run_state())
        .or(inputs.report_state())
        .unwrap_or(WorkbenchState::Review)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use kuzushi_core::{V2Config, WorkflowPhase};
    use std::cell::Cell;

    fn app() -> ShellApp {
        ShellApp::new(V2Config::default(), None)
    }

    fn no_selection() -> SelectedFindingHints<'static> {
        SelectedFindingHints::default()
    }

    fn selected(reference: &str, awaiting_patch_draft: bool) -> SelectedFindingHints<'_> {
        SelectedFindingHints {
            has_detail: true,
            reference: Some(reference),
            awaiting_patch_draft,
        }
    }

    fn fix_patch_hint(selection: SelectedFindingHints<'_>) -> WorkbenchHint {
        command_bar_hints(&app(), WorkbenchPage::Fix, None, selection)
            .into_iter()
            .next()
            .expect("fix hint row")
    }

    #[test]
    fn undrafted_fix_selection_offers_to_draft_a_patch_by_alias() {
        assert_eq!(
            fix_patch_hint(selected("F-0001", true)),
            WorkbenchHint {
                verb: Cow::Borrowed("patch F-0001"),
                label: Cow::Borrowed("draft a patch"),
            }
        );
        assert_eq!(
            fix_patch_hint(selected("F-0001", false)).label,
            "patch displayed"
        );
        assert_eq!(fix_patch_hint(no_selection()).verb, "run patch:finding");
    }

    #[test]
    fn reverify_control_names_the_active_input_mode_contract() {
        let mut app = app();

        assert_eq!(workbench_reverify_control_hint(&app), "Esc then v");
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE))
                .handled
        );
        assert_eq!(app.input(), "v");
        app.set_input("unfinished draft".to_string());
        assert_eq!(
            workbench_reverify_control_hint(&app),
            "clear prompt then Esc then v"
        );
        app.set_input(String::new());
        app.set_input_mode(crate::InputMode::Navigate);
        assert_eq!(workbench_reverify_control_hint(&app), "v");
    }

    #[test]
    fn reverify_control_uses_the_resolved_navigate_mode_binding() {
        let mut config = V2Config::default();
        config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
            context: "composer".to_string(),
            action: "navigate_mode".to_string(),
            bindings: vec!["ctrl+x".to_string()],
        }];
        let app = ShellApp::new(config, None);

        assert_eq!(workbench_reverify_control_hint(&app), "ctrl+x then v");
        let hints = command_bar_hints(&app, WorkbenchPage::Fix, None, no_selection());
        assert!(hints.iter().any(|hint| {
            hint.verb == "ctrl+x then v" && hint.label == "reverify applied patch"
        }));
    }

    #[test]
    fn phase_hints_externalize_review_decisions_and_prior_runs() {
        let prompt_app = app();

        let review = command_bar_hints(&prompt_app, WorkbenchPage::Review, None, no_selection());
        assert!(review
            .iter()
            .any(|hint| { hint.verb == "Esc then B" && hint.label == "review decision backlog" }));

        let mut navigate = app();
        navigate.set_input_mode(crate::InputMode::Navigate);
        let review = command_bar_hints(&navigate, WorkbenchPage::Review, None, no_selection());
        assert!(review
            .iter()
            .any(|hint| hint.verb == "B" && hint.label == "review decision backlog"));

        let map = command_bar_hints(&prompt_app, WorkbenchPage::Map, None, no_selection());
        assert!(map
            .iter()
            .any(|hint| hint.verb == "jobs" && hint.label == "inspect Map runs"));
    }

    #[test]
    fn map_zoom_hint_names_the_mode_transition_before_the_view_key() {
        let mut app = app();
        let hints = command_bar_hints(&app, WorkbenchPage::Map, None, no_selection());
        assert!(hints.iter().any(|hint| hint.verb == "Esc then z"));
        app.set_input_mode(crate::InputMode::Navigate);
        let hints = command_bar_hints(&app, WorkbenchPage::Map, None, no_selection());
        assert!(hints.iter().any(|hint| hint.verb == "z"));
    }

    #[test]
    fn empty_review_names_queue_recovery_without_a_heatmap() {
        let hints = page_command_bar_hints(&app(), WorkbenchPage::Review);

        assert!(hints
            .iter()
            .any(|hint| hint.verb == "findings" && hint.label == "full queue"));
        assert!(!hints.iter().any(|hint| hint.verb == "z"));
    }

    #[test]
    fn populated_review_keeps_the_heatmap_hint() {
        let mut app = app();
        app.set_findings(vec![kuzushi_core::Finding::new_tool(
            "agentic-sast",
            "rule",
            "src/lib.rs",
            4,
            None,
            kuzushi_core::Severity::High,
            "prior observation",
        )]);

        let hints = page_command_bar_hints(&app, WorkbenchPage::Review);

        assert!(hints
            .iter()
            .any(|hint| hint.verb == "z" && hint.label == "open heatmap"));
    }

    /// Item: a Prove page with nothing selected sends the operator to Review,
    /// so the hint must carry Review's own page key. `2` reaches Scan, which
    /// has no finding to choose.
    #[test]
    fn detail_free_prove_hint_names_the_review_page_key() {
        let hints = command_bar_hints(&app(), WorkbenchPage::Prove, None, no_selection());

        assert_eq!(
            hints[0],
            WorkbenchHint {
                verb: Cow::Owned(WorkbenchPage::Review.page_key().to_string()),
                label: Cow::Borrowed("choose a finding in Review"),
            }
        );
    }

    #[test]
    fn staged_fix_hints_replace_the_unavailable_reverify_action() {
        let mut app = app();
        app.engagement.set_pending_patch(crate::app::PendingPatch {
            alias: "F-0001".to_string(),
            patch_run_id: "patch-run".to_string(),
            status: kuzushi_core::PatchStatus::Sound,
            rationale: "bind the value".to_string(),
            side_effect: None,
            diff: "--- a/x\n+++ b/x\n".to_string(),
            tests: Vec::new(),
            guardrail: None,
            staged_at: None,
        });

        let hints = command_bar_hints(&app, WorkbenchPage::Fix, None, selected("F-0001", false));

        assert!(hints
            .iter()
            .any(|hint| hint.verb == "patch apply" && hint.label == "write reviewed diff"));
        assert!(hints
            .iter()
            .any(|hint| hint.verb == "patch reject" && hint.label == "discard candidate"));
        assert!(hints
            .iter()
            .any(|hint| hint.verb == "patch regen" && hint.label == "replace candidate"));
        assert!(!hints.iter().any(|hint| hint.label.contains("reverify")));
    }

    #[test]
    fn page_names_map_persisted_phases_to_operator_language() {
        assert_eq!(
            WorkbenchPage::from_phase(WorkflowPhase::Map),
            WorkbenchPage::Map
        );
        assert_eq!(
            WorkbenchPage::from_phase(WorkflowPhase::Scan),
            WorkbenchPage::Scan
        );
        assert_eq!(
            WorkbenchPage::from_phase(WorkflowPhase::Review),
            WorkbenchPage::Review
        );
        assert_eq!(
            WorkbenchPage::from_phase(WorkflowPhase::Prove),
            WorkbenchPage::Prove
        );
        assert_eq!(
            WorkbenchPage::from_phase(WorkflowPhase::Fix),
            WorkbenchPage::Fix
        );
    }

    #[test]
    fn explicit_page_selection_owns_the_active_durable_page() {
        let mut app = app();
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Map));
        let journey_builds = Cell::new(0);

        let page = active_workbench_page_with_phase_builder(&app, |_| {
            journey_builds.set(journey_builds.get() + 1);
            None
        });

        assert_eq!(page, WorkbenchPage::Map);
        assert_eq!(journey_builds.get(), 0);
    }

    #[test]
    fn future_pages_remain_browsable_without_advancing_reality() {
        let target = tempfile::tempdir().expect("target");
        let mut app = app();
        app.set_target(Some(target.path().to_path_buf()));

        app.set_workbench_page(WorkbenchPage::Review);
        assert_eq!(active_workbench_page(&app), WorkbenchPage::Review);
        let journey = journey_model(&app).expect("journey");
        assert_eq!(journey.current, WorkflowPhase::Map);
        assert_eq!(journey.phases[0].navigation_symbol(), "●");
        assert_eq!(journey.phases[1].navigation_symbol(), "×");
        assert_eq!(journey.phases[2].navigation_symbol(), "×");
    }

    #[test]
    fn durable_findings_populate_review_without_advancing_reality() {
        let target = tempfile::tempdir().expect("target");
        let mut app = app();
        app.set_target(Some(target.path().to_path_buf()));
        app.set_findings(vec![kuzushi_core::Finding::new_tool(
            "agentic-sast",
            "rule",
            "src/lib.rs",
            4,
            None,
            kuzushi_core::Severity::High,
            "prior observation",
        )]);

        app.set_workbench_page(WorkbenchPage::Review);
        assert_eq!(active_workbench_page(&app), WorkbenchPage::Review);
        let journey = journey_model(&app).unwrap();
        assert_eq!(journey.current, WorkflowPhase::Map);
        assert_eq!(journey.phases[2].navigation_symbol(), "○");
    }

    #[test]
    fn presentation_snapshot_builds_and_reuses_one_journey_model() {
        let target = tempfile::tempdir().expect("target");
        let mut app = app();
        app.set_target(Some(target.path().to_path_buf()));
        let journey_builds = Cell::new(0);

        let snapshot = build_workbench_presentation_snapshot(&app, |app| {
            journey_builds.set(journey_builds.get() + 1);
            journey_model(app)
        });

        assert_eq!(journey_builds.get(), 1);
        assert_eq!(snapshot.phase.phase, snapshot.page.phase());
        assert_eq!(snapshot.chrome.page, snapshot.page);
        assert_eq!(
            snapshot.phase.header.phase_rail,
            snapshot.chrome.top_bar.phase_rail
        );
        assert_eq!(
            snapshot
                .phase
                .header
                .reality_phase
                .map(WorkbenchPage::from_phase),
            Some(snapshot.page)
        );
    }

    #[test]
    fn report_command_opens_the_dedicated_exit_surface() {
        assert_eq!(
            workbench_report_command(ReviewQueueMode::Complete),
            "report"
        );
    }
}
