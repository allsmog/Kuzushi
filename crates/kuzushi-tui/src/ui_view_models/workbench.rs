//! View-model for the Workbench command center (`ShellView::Workbench`).
//!
//! Pure composition over the existing finding / code / DFD / journey view-models.
//! The renderer and the plain `workbench_lines` path both consume this single
//! model so TTY and scripted output stay in lockstep.

use super::{
    attack_tree, cached_findings_heatmap_with_selection, dfd_model, findings_model, journey_model,
    journey_phase_segment, review_queue_model, selected_finding_code_model,
    selected_finding_detail_model, selected_taint_flow_path, source_tree_model, threat_model_doc,
    CodePaneModel, FindingDetailModel, FindingsModel, JourneyPhaseStatus, ReviewQueueMode,
    ReviewQueueModel, SourceTreeModel,
};
use crate::app::{WorkbenchCenterMode, WorkbenchPage, WorkbenchPane, WorkflowPhase};
use crate::ShellApp;
use kuzushi_core::findings::FindingReviewCompletenessFilter;
use kuzushi_core::FindingListFilter;
use std::borrow::Cow;

/// Which workflow posture the Workbench is in, derived from app signals. Drives
/// truthful pane titles / empty-hints, never invented content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkbenchState {
    /// Nothing produced yet: no findings and no threat-model artifact.
    FirstRun,
    /// A scan or tool run is live (same signal as the LIVE dot).
    Scanning,
    /// Findings and/or a threat model exist; the operator is browsing.
    Review,
    /// A finding is selected — the DETAILS pane is the focus of attention.
    FindingDetail,
    /// The engagement has reached 掛 fix: everything confirmed, patch/report.
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchTopBar {
    pub(crate) brand: &'static str,
    /// `./project` directory name, or `no target` when none is set.
    pub(crate) project: String,
    /// Focused module, or `all modules` when none is focused.
    pub(crate) target: String,
    /// Lit only on real executing work (scan/tool/agent/planner/threat worker).
    pub(crate) live: bool,
    /// `組 map 1/4`-style chip, or `None` without a target.
    pub(crate) phase: Option<String>,
    /// Active cockpit page.
    pub(crate) page: WorkbenchPage,
    /// Full engagement rail for default Workbench orientation.
    pub(crate) phase_rail: Vec<JourneyPhaseStatus>,
    /// Compact NEXT summary for the current phase.
    pub(crate) phase_next_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchCenter {
    pub(crate) title: String,
    pub(crate) context: Option<String>,
    pub(crate) active_mode: WorkbenchCenterMode,
    pub(crate) tabs: Vec<WorkbenchCenterTab>,
    pub(crate) body: WorkbenchCenterBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchCenterTab {
    pub(crate) mode: WorkbenchCenterMode,
    pub(crate) label: &'static str,
    pub(crate) active: bool,
    pub(crate) empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkbenchCenterBody {
    Code(Option<CodePaneModel>),
    Dfd {
        /// `Some` when no DFD artifact exists — the pane shows one guidance line.
        empty_hint: Option<String>,
    },
    Chain {
        empty_hint: Option<String>,
    },
    Flow {
        empty_hint: Option<String>,
    },
    Risk {
        empty_hint: Option<String>,
    },
}

/// A command-bar label that maps to an existing shell verb (no new tool paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchHint {
    pub(crate) verb: Cow<'static, str>,
    pub(crate) label: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchViewModel {
    pub(crate) page: WorkbenchPage,
    pub(crate) top_bar: WorkbenchTopBar,
    pub(crate) left: SourceTreeModel,
    pub(crate) center: WorkbenchCenter,
    pub(crate) right_list: FindingsModel,
    pub(crate) review_queue: ReviewQueueModel,
    pub(crate) right_detail: Option<FindingDetailModel>,
    pub(crate) command_bar_hints: Vec<WorkbenchHint>,
    pub(crate) report_cta: Option<WorkbenchHint>,
    pub(crate) state: WorkbenchState,
    pub(crate) focus: WorkbenchPane,
    pub(crate) zoom: Option<WorkbenchPane>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchChromeModel {
    pub(crate) page: WorkbenchPage,
    pub(crate) top_bar: WorkbenchTopBar,
    pub(crate) command_bar_hints: Vec<WorkbenchHint>,
    pub(crate) zoom: Option<WorkbenchPane>,
}

pub(crate) const WORKBENCH_REPORT_COMMAND: &str = "findings export report.sarif sarif";

const REVIEW_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    WorkbenchHint {
        verb: Cow::Borrowed("next"),
        label: "guided workflow",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("scan"),
        label: "guided plan",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("options sast:scan"),
        label: "tune scanners",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("ask"),
        label: "ask the agent",
    },
];

const TERRAIN_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    WorkbenchHint {
        verb: Cow::Borrowed("next"),
        label: "map target",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("context build"),
        label: "build context",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("attach <path>"),
        label: "seed materials",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("ask"),
        label: "ask about terrain",
    },
];

const COVERAGE_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    WorkbenchHint {
        verb: Cow::Borrowed("strategy"),
        label: "proposal queue",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("recommend"),
        label: "generate proposals",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("scan"),
        label: "fire hunt",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("ask"),
        label: "steer focus",
    },
];

const SHIP_COMMAND_BAR_HINTS: [WorkbenchHint; 4] = [
    WorkbenchHint {
        verb: Cow::Borrowed("c"),
        label: "order exploit chain",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("run patch:finding"),
        label: "patch selected",
    },
    WorkbenchHint {
        verb: Cow::Borrowed(WORKBENCH_REPORT_COMMAND),
        label: "export report",
    },
    WorkbenchHint {
        verb: Cow::Borrowed("ask"),
        label: "ask about shipping",
    },
];

const REPORT_HINT: WorkbenchHint = WorkbenchHint {
    verb: Cow::Borrowed(WORKBENCH_REPORT_COMMAND),
    label: "export SARIF",
};

pub(crate) fn workbench_view_model(app: &ShellApp) -> WorkbenchViewModel {
    let page = active_workbench_page(app);
    let state = workbench_state(app);
    let right_list = findings_model(app);
    let review_mode = active_review_queue_mode(app);
    let review_queue = review_queue_model(app, review_mode);
    let report_cta = report_cta(state, right_list.total, review_mode);
    let right_detail = selected_finding_detail_model(app);
    let chrome = chrome_model(
        app,
        page,
        report_cta.clone(),
        right_detail.is_some(),
        right_detail
            .as_ref()
            .map(|detail| detail.fingerprint.as_str()),
    );
    WorkbenchViewModel {
        page,
        top_bar: chrome.top_bar,
        left: source_tree_model(app),
        center: center_model(app, right_detail.as_ref()),
        right_list,
        review_queue,
        command_bar_hints: chrome.command_bar_hints,
        right_detail,
        report_cta,
        state,
        focus: app.router.workbench().focus(),
        zoom: chrome.zoom,
    }
}

pub(crate) fn workbench_chrome_model(
    app: &ShellApp,
    page: WorkbenchPage,
    detail: Option<&FindingDetailModel>,
) -> WorkbenchChromeModel {
    workbench_chrome_model_for_selection(
        app,
        page,
        detail.is_some(),
        detail.map(|detail| detail.fingerprint.as_str()),
    )
}

pub(crate) fn workbench_chrome_model_for_selection(
    app: &ShellApp,
    page: WorkbenchPage,
    has_detail: bool,
    fingerprint: Option<&str>,
) -> WorkbenchChromeModel {
    let state = workbench_state(app);
    let mode = active_review_queue_mode(app);
    let report_cta = report_cta(state, super::visible_findings_len(app), mode);
    chrome_model(app, page, report_cta, has_detail, fingerprint)
}

fn chrome_model(
    app: &ShellApp,
    page: WorkbenchPage,
    report_cta: Option<WorkbenchHint>,
    has_detail: bool,
    fingerprint: Option<&str>,
) -> WorkbenchChromeModel {
    WorkbenchChromeModel {
        page,
        top_bar: top_bar_model(app, page),
        command_bar_hints: command_bar_hints(page, report_cta, has_detail, fingerprint),
        zoom: app.router.workbench().zoom().pane(),
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

pub(crate) fn workbench_export_command(
    command: &'static str,
    mode: ReviewQueueMode,
) -> Cow<'static, str> {
    match mode {
        ReviewQueueMode::All => Cow::Borrowed(command),
        ReviewQueueMode::Open | ReviewQueueMode::Complete => {
            Cow::Owned(format!("{command} --completeness {}", mode.label()))
        }
    }
}

pub(crate) fn workbench_report_command(mode: ReviewQueueMode) -> Cow<'static, str> {
    workbench_export_command(WORKBENCH_REPORT_COMMAND, mode)
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
    app.router
        .workbench()
        .page()
        .or_else(|| {
            app.target_path_buf().and_then(|_| {
                journey_model(app).map(|journey| WorkbenchPage::from_phase(journey.current))
            })
        })
        .unwrap_or(WorkbenchPage::Review)
}

fn command_bar_hints(
    page: WorkbenchPage,
    report_cta: Option<WorkbenchHint>,
    has_detail: bool,
    fingerprint: Option<&str>,
) -> Vec<WorkbenchHint> {
    if page == WorkbenchPage::Review && has_detail {
        return review_decision_hints(report_cta);
    }
    let mut hints = page_command_bar_hints(page);
    customize_page_hints(&mut hints, page, fingerprint);
    append_report_hint(&mut hints, report_cta);
    hints
}

fn review_decision_hints(report_cta: Option<WorkbenchHint>) -> Vec<WorkbenchHint> {
    let mut hints = vec![
        WorkbenchHint {
            verb: Cow::Borrowed("decision confirmed|false-positive|suppressed <reason>"),
            label: "review",
        },
        WorkbenchHint {
            verb: Cow::Borrowed("dismiss false_positive <note>"),
            label: "dismiss",
        },
    ];
    hints.extend(report_cta);
    hints
}

fn customize_page_hints(
    hints: &mut [WorkbenchHint],
    page: WorkbenchPage,
    fingerprint: Option<&str>,
) {
    if page == WorkbenchPage::Ship {
        replace_patch_hint(hints, fingerprint);
    }
}

fn append_report_hint(hints: &mut Vec<WorkbenchHint>, report_cta: Option<WorkbenchHint>) {
    let Some(report_cta) = report_cta else {
        return;
    };
    replace_report_hint(hints, &report_cta);
    if !hints.iter().any(|hint| hint.verb == report_cta.verb) {
        hints.push(report_cta);
    }
}

fn replace_patch_hint(hints: &mut [WorkbenchHint], fingerprint: Option<&str>) {
    let Some(fingerprint) = fingerprint else {
        return;
    };
    let Some(hint) = hints.iter_mut().find(|hint| hint.label == "patch selected") else {
        return;
    };
    hint.verb = Cow::Owned(format!(
        "run patch:finding {{\"fingerprint\":\"{}\"}}",
        fingerprint
    ));
}

fn replace_report_hint(hints: &mut [WorkbenchHint], report_cta: &WorkbenchHint) {
    let Some(hint) = hints
        .iter_mut()
        .find(|hint| hint.verb == WORKBENCH_REPORT_COMMAND)
    else {
        return;
    };
    hint.verb = report_cta.verb.clone();
}

fn page_command_bar_hints(page: WorkbenchPage) -> Vec<WorkbenchHint> {
    page_command_bar_hint_slice(page).to_vec()
}

fn page_command_bar_hint_slice(page: WorkbenchPage) -> &'static [WorkbenchHint] {
    match page {
        WorkbenchPage::Terrain => &TERRAIN_COMMAND_BAR_HINTS,
        WorkbenchPage::Coverage => &COVERAGE_COMMAND_BAR_HINTS,
        WorkbenchPage::Review => &REVIEW_COMMAND_BAR_HINTS,
        WorkbenchPage::Ship => &SHIP_COMMAND_BAR_HINTS,
    }
}

fn report_cta(
    state: WorkbenchState,
    finding_total: usize,
    mode: ReviewQueueMode,
) -> Option<WorkbenchHint> {
    (state == WorkbenchState::Report || finding_total > 0).then(|| WorkbenchHint {
        verb: workbench_report_command(mode),
        ..REPORT_HINT
    })
}

fn top_bar_model(app: &ShellApp, page: WorkbenchPage) -> WorkbenchTopBar {
    let journey = journey_model(app);
    WorkbenchTopBar {
        brand: "Kuzushi",
        project: project_label(app),
        target: target_label(app),
        live: app.has_running_work(),
        phase: journey
            .as_ref()
            .map(|journey| journey_phase_segment(journey.current)),
        page,
        phase_rail: journey
            .as_ref()
            .map(|journey| journey.phases.clone())
            .unwrap_or_default(),
        phase_next_summary: journey.map(|journey| journey.next_summary),
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

fn center_model(app: &ShellApp, detail: Option<&FindingDetailModel>) -> WorkbenchCenter {
    let code = selected_finding_code_model(app);
    let active_mode = app.router.workbench().center_mode();
    let context = center_context(detail);
    let tabs = center_tabs(app, code.as_ref(), active_mode);
    let body = center_body(app, code, active_mode);
    WorkbenchCenter {
        title: center_title(&tabs, context.as_deref()),
        context,
        active_mode,
        tabs,
        body,
    }
}

fn center_body(
    app: &ShellApp,
    code: Option<CodePaneModel>,
    mode: WorkbenchCenterMode,
) -> WorkbenchCenterBody {
    match mode {
        WorkbenchCenterMode::Code => WorkbenchCenterBody::Code(code),
        WorkbenchCenterMode::Dfd => WorkbenchCenterBody::Dfd {
            empty_hint: dfd_model(app).empty_hint,
        },
        WorkbenchCenterMode::Chain => WorkbenchCenterBody::Chain {
            empty_hint: attack_tree(app).empty_hint,
        },
        WorkbenchCenterMode::Flow => WorkbenchCenterBody::Flow {
            empty_hint: selected_taint_flow_path(app).empty_hint,
        },
        WorkbenchCenterMode::Risk => WorkbenchCenterBody::Risk {
            empty_hint: cached_findings_heatmap_with_selection(
                app,
                app.selected_finding().as_ref(),
            )
            .empty_hint,
        },
    }
}

fn center_tabs(
    app: &ShellApp,
    code: Option<&CodePaneModel>,
    active_mode: WorkbenchCenterMode,
) -> Vec<WorkbenchCenterTab> {
    WorkbenchCenterMode::ALL
        .iter()
        .map(|&mode| WorkbenchCenterTab {
            mode,
            label: mode.label(),
            active: mode == active_mode,
            empty: center_tab_empty(app, code, mode),
        })
        .collect()
}

fn center_tab_empty(
    app: &ShellApp,
    code: Option<&CodePaneModel>,
    mode: WorkbenchCenterMode,
) -> bool {
    match mode {
        WorkbenchCenterMode::Code => code.map_or(true, |code| code.empty_hint.is_some()),
        WorkbenchCenterMode::Dfd => dfd_model(app).empty_hint.is_some(),
        WorkbenchCenterMode::Chain => !app.domain().has_exploit_chains(),
        WorkbenchCenterMode::Flow => selected_taint_flow_path(app).empty_hint.is_some(),
        WorkbenchCenterMode::Risk => cached_findings_heatmap_with_selection(app, None)
            .empty_hint
            .is_some(),
    }
}

fn center_context(detail: Option<&FindingDetailModel>) -> Option<String> {
    let detail = detail?;
    Some(format!(
        "{} · {}",
        detail.alias.as_deref().unwrap_or("selected"),
        detail.location
    ))
}

fn center_title(tabs: &[WorkbenchCenterTab], context: Option<&str>) -> String {
    let mut title = tabs
        .iter()
        .map(plain_tab_label)
        .collect::<Vec<_>>()
        .join(" │ ");
    if let Some(context) = context {
        title.push_str(" ── ");
        title.push_str(context);
    }
    title
}

fn plain_tab_label(tab: &WorkbenchCenterTab) -> String {
    let mut label = tab.label.to_string();
    if tab.empty {
        label.push('·');
    }
    if tab.active {
        format!("[{label}]")
    } else {
        format!(" {label} ")
    }
}

fn workbench_state(app: &ShellApp) -> WorkbenchState {
    derive_state(WorkbenchStateInputs {
        scanning: app.has_running_work(),
        selected: app.selected_finding().is_some(),
        has_findings: !app.findings().is_empty(),
        has_threat_doc: threat_model_doc(app).is_some(),
        at_fix: journey_model(app).is_some_and(|journey| journey.current == WorkflowPhase::Fix),
    })
}

/// Pure inputs to the state machine, so the priority logic is testable without
/// a live `ShellApp` or filesystem.
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
}

/// Live work and an open finding take precedence; everything else resolves in
/// `derive_quiescent_state`.
fn derive_state(inputs: WorkbenchStateInputs) -> WorkbenchState {
    if inputs.scanning {
        return WorkbenchState::Scanning;
    }
    if inputs.selected {
        return WorkbenchState::FindingDetail;
    }
    derive_quiescent_state(inputs)
}

fn derive_quiescent_state(inputs: WorkbenchStateInputs) -> WorkbenchState {
    if inputs.is_first_run() {
        return WorkbenchState::FirstRun;
    }
    if inputs.at_fix {
        return WorkbenchState::Report;
    }
    WorkbenchState::Review
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::JourneyPhaseState;
    use kuzushi_core::{Finding, Severity, V2Config};

    fn app() -> ShellApp {
        ShellApp::new(V2Config::default(), None)
    }

    fn finding(severity: Severity) -> Finding {
        finding_at("crates/foo.rs", severity)
    }

    fn finding_at(file_path: &str, severity: Severity) -> Finding {
        Finding::new_semgrep("demo.rule", file_path, 12, None, severity, "title")
    }

    fn inputs() -> WorkbenchStateInputs {
        WorkbenchStateInputs {
            scanning: false,
            selected: false,
            has_findings: false,
            has_threat_doc: false,
            at_fix: false,
        }
    }

    #[test]
    fn live_is_off_with_no_activity() {
        let model = workbench_view_model(&app());
        assert!(!model.top_bar.live);
    }

    #[test]
    fn live_is_on_with_a_running_scan() {
        let mut app = app();
        app.set_scan_panel(Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));
        let model = workbench_view_model(&app);
        assert!(model.top_bar.live);
        assert_eq!(model.state, WorkbenchState::Scanning);
    }

    #[test]
    fn live_is_on_with_agentic_background_work() {
        let setups: [fn(&mut ShellApp); 3] = [
            |app: &mut ShellApp| app.set_planner_running(true),
            |app: &mut ShellApp| app.set_threat_worker_running(true),
            |app: &mut ShellApp| {
                app.set_agent_chat(Some(crate::app::AgentChatView {
                    question: "q".to_string(),
                    running: true,
                    ..Default::default()
                }));
            },
        ];
        for setup in setups {
            let mut app = app();
            setup(&mut app);

            let model = workbench_view_model(&app);

            assert!(model.top_bar.live);
            assert_eq!(model.state, WorkbenchState::Scanning);
        }
    }

    #[test]
    fn top_bar_includes_phase_chip_and_phase_rail_when_target_is_set() {
        let target = tempfile::tempdir().unwrap();
        let mut app = app();
        app.set_target(Some(target.path().to_path_buf()));

        let model = workbench_view_model(&app);

        assert_eq!(model.top_bar.phase.as_deref(), Some("組 map 1/4"));
        assert_eq!(model.top_bar.phase_rail.len(), 4);
        assert_eq!(
            model.top_bar.phase_next_summary.as_deref(),
            Some("組 map · build context and analysis artifacts — next to continue")
        );
        assert_eq!(
            model.top_bar.phase_rail[0].state,
            JourneyPhaseState::Current
        );
        assert_eq!(
            model.top_bar.phase_rail[1].state,
            JourneyPhaseState::Pending
        );
    }

    #[test]
    fn top_bar_omits_journey_chrome_without_a_target() {
        let model = workbench_view_model(&app());

        assert_eq!(model.top_bar.phase, None);
        assert!(model.top_bar.phase_rail.is_empty());
        assert_eq!(model.top_bar.phase_next_summary, None);
    }

    #[test]
    fn top_bar_rail_tracks_workspace_reality_not_open_page() {
        let target = tempfile::tempdir().unwrap();
        let mut app = app();
        app.set_target(Some(target.path().to_path_buf()));
        *app.findings_mut() = vec![finding(Severity::High)];
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Terrain));

        let model = workbench_view_model(&app);

        assert_eq!(model.page, WorkbenchPage::Terrain);
        assert_eq!(model.top_bar.phase.as_deref(), Some("作 confirm 3/4"));
        assert_eq!(model.top_bar.phase_rail[0].state, JourneyPhaseState::Done);
        assert_eq!(model.top_bar.phase_rail[1].state, JourneyPhaseState::Done);
        assert_eq!(
            model.top_bar.phase_rail[2].state,
            JourneyPhaseState::Current
        );
        assert_eq!(
            model.top_bar.phase_next_summary.as_deref(),
            Some("作 confirm · 1 findings need review — next to continue")
        );
    }

    #[test]
    fn first_run_state_with_no_findings_and_no_doc() {
        let model = workbench_view_model(&app());
        assert_eq!(model.state, WorkbenchState::FirstRun);
        assert!(model.report_cta.is_none());
        assert!(!model
            .command_bar_hints
            .iter()
            .any(|hint| hint.verb == WORKBENCH_REPORT_COMMAND));
        assert!(matches!(model.center.body, WorkbenchCenterBody::Code(None)));
        assert!(model
            .center
            .tabs
            .iter()
            .any(|tab| { tab.mode == WorkbenchCenterMode::Dfd && tab.empty && !tab.active }));
        assert!(model.left.empty_hint.is_some());
    }

    #[test]
    fn center_tabs_mark_active_page_and_empty_artifacts() {
        let mut app = app();
        app.router
            .workbench_mut()
            .set_center_mode(WorkbenchCenterMode::Risk);

        let model = workbench_view_model(&app);

        assert!(model.center.title.contains("[RISK·]"));
        assert!(model
            .center
            .tabs
            .iter()
            .any(|tab| { tab.mode == WorkbenchCenterMode::Risk && tab.active && tab.empty }));
        assert!(model
            .center
            .tabs
            .iter()
            .any(|tab| { tab.mode == WorkbenchCenterMode::Dfd && !tab.active && tab.empty }));
    }

    #[test]
    fn risk_tab_empty_state_matches_heatmap_for_unknown_severity_findings() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::Unknown)];
        app.router
            .workbench_mut()
            .set_center_mode(WorkbenchCenterMode::Risk);

        let model = workbench_view_model(&app);

        assert!(model
            .center
            .tabs
            .iter()
            .any(|tab| { tab.mode == WorkbenchCenterMode::Risk && tab.active && tab.empty }));
        assert!(matches!(
            model.center.body,
            WorkbenchCenterBody::Risk {
                empty_hint: Some(_)
            }
        ));
    }

    #[test]
    fn findings_surface_report_export_cta() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];

        let model = workbench_view_model(&app);

        assert_eq!(
            model.report_cta.as_ref().map(|hint| hint.verb.as_ref()),
            Some(WORKBENCH_REPORT_COMMAND)
        );
        assert!(model
            .command_bar_hints
            .iter()
            .any(|hint| hint.verb == WORKBENCH_REPORT_COMMAND));
    }

    #[test]
    fn report_export_cta_tracks_active_review_completeness_filter() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        app.set_active_findings_filter(Some("completeness:open".to_string()));
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Ship));

        let model = workbench_view_model(&app);
        let expected = "findings export report.sarif sarif --completeness open";
        let report_hints = model
            .command_bar_hints
            .iter()
            .filter(|hint| hint.label == "export report")
            .collect::<Vec<_>>();

        assert_eq!(
            model.report_cta.as_ref().map(|hint| hint.verb.as_ref()),
            Some(expected)
        );
        assert_eq!(report_hints.len(), 1);
        assert_eq!(report_hints[0].verb.as_ref(), expected);
    }

    #[test]
    fn report_state_surfaces_report_export_cta() {
        assert_eq!(
            report_cta(WorkbenchState::Report, 0, ReviewQueueMode::All)
                .as_ref()
                .map(|hint| hint.verb.as_ref()),
            Some(WORKBENCH_REPORT_COMMAND)
        );
    }

    #[test]
    fn ship_page_patch_hint_includes_selected_finding_fingerprint() {
        let mut app = app();
        let selected = finding(Severity::High);
        let fingerprint = selected.fingerprint.clone();
        *app.findings_mut() = vec![selected.clone()];
        *app.selected_finding_mut() = Some(selected);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Ship));

        let model = workbench_view_model(&app);

        let patch = model
            .command_bar_hints
            .iter()
            .find(|hint| hint.label == "patch selected")
            .expect("patch hint");
        assert!(patch.verb.contains("run patch:finding"));
        assert!(patch.verb.contains(&fingerprint));
    }

    #[test]
    fn finding_detail_state_when_a_finding_is_selected() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        *app.selected_finding_mut() = Some(finding(Severity::High));
        let model = workbench_view_model(&app);
        assert_eq!(model.state, WorkbenchState::FindingDetail);
        assert!(model.right_detail.is_some());
        assert!(matches!(model.center.body, WorkbenchCenterBody::Code(_)));
        assert!(model.command_bar_hints.iter().any(|hint| {
            hint.verb.contains("false-positive") && hint.verb.contains("suppressed")
        }));
        assert!(model
            .command_bar_hints
            .iter()
            .any(|hint| hint.verb.starts_with("dismiss ")));
    }

    #[test]
    fn detail_preview_follows_cursor_before_pinned_selection() {
        let mut app = app();
        let mut first = finding(Severity::High);
        first.fingerprint = "a-first".to_string();
        first.title = "first selected".to_string();
        let mut second = finding(Severity::High);
        second.fingerprint = "b-second".to_string();
        second.title = "second cursor".to_string();
        app_with_findings_cursor(&mut app, first.clone(), second.clone());

        let model = workbench_view_model(&app);

        assert_eq!(model.right_detail.unwrap().title, "second cursor");
        match model.center.body {
            WorkbenchCenterBody::Code(Some(code)) => {
                assert!(code.title.contains("F-0002"), "{:?}", code.title);
            }
            _ => panic!("expected code preview"),
        }
    }

    #[test]
    fn center_focus_keeps_code_preview_when_selected_finding() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        *app.selected_finding_mut() = Some(app.findings()[0].clone());
        app.router.workbench_mut().set_focus(WorkbenchPane::Center);

        let model = workbench_view_model(&app);

        assert!(matches!(model.center.body, WorkbenchCenterBody::Code(_)));
    }

    #[test]
    fn center_mode_can_explicitly_show_dfd_with_selected_finding() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        *app.selected_finding_mut() = Some(app.findings()[0].clone());
        app.router.workbench_mut().set_focus(WorkbenchPane::Center);
        app.router
            .workbench_mut()
            .set_center_mode(WorkbenchCenterMode::Dfd);

        let model = workbench_view_model(&app);

        assert!(matches!(model.center.body, WorkbenchCenterBody::Dfd { .. }));
    }

    fn app_with_findings_cursor(app: &mut ShellApp, first: Finding, second: Finding) {
        *app.findings_mut() = vec![first.clone(), second];
        *app.selected_finding_mut() = Some(first);
        app.router.findings_mut().set_cursor(1);
    }

    #[test]
    fn severity_chip_counts_reflect_findings() {
        let mut app = app();
        *app.findings_mut() = vec![
            finding_at("crates/critical.rs", Severity::Critical),
            finding_at("crates/high_a.rs", Severity::High),
            finding_at("crates/high_b.rs", Severity::High),
            finding_at("crates/low.rs", Severity::Low),
        ];
        let counts = workbench_view_model(&app).right_list.counts;
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 2);
        assert_eq!(counts.low, 1);
    }

    #[test]
    fn severity_chip_counts_use_engagement_projection() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::Medium), finding(Severity::High)];
        let right_list = workbench_view_model(&app).right_list;
        assert_eq!(right_list.total, 1);
        assert_eq!(right_list.counts.high, 1);
        assert_eq!(right_list.counts.medium, 0);
    }

    #[test]
    fn source_tree_counts_use_engagement_projection() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::Medium), finding(Severity::High)];

        let model = workbench_view_model(&app);

        assert_eq!(model.right_list.total, 1);
        assert_eq!(model.left.finding_count, 1);
        assert_eq!(model.left.file_count, 1);
    }

    #[test]
    fn review_queue_mode_follows_active_completeness_filter() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        app.set_active_findings_filter(Some("decision:needs_review completeness:open".to_string()));

        let model = workbench_view_model(&app);

        assert_eq!(model.review_queue.completeness_mode, "open");
        assert_eq!(
            model.review_queue.filter_label,
            "decision:needs_review completeness:open"
        );
        assert_eq!(model.review_queue.visible_count, 1);
    }

    #[test]
    fn review_queue_mode_defaults_to_all_for_ambiguous_completeness_filter() {
        let mut app = app();
        *app.findings_mut() = vec![finding(Severity::High)];
        app.set_active_findings_filter(Some("completeness:open completeness:complete".to_string()));

        let model = workbench_view_model(&app);

        assert_eq!(model.review_queue.completeness_mode, "all");
        assert_eq!(
            model.review_queue.filter_label,
            "completeness:open completeness:complete"
        );
    }

    #[test]
    fn scanning_outranks_selection() {
        let mut i = inputs();
        i.scanning = true;
        i.selected = true;
        assert_eq!(derive_state(i), WorkbenchState::Scanning);
    }

    #[test]
    fn review_when_findings_exist_off_the_fix_phase() {
        let mut i = inputs();
        i.has_findings = true;
        assert_eq!(derive_state(i), WorkbenchState::Review);
    }

    #[test]
    fn report_at_the_fix_phase() {
        let mut i = inputs();
        i.has_findings = true;
        i.at_fix = true;
        assert_eq!(derive_state(i), WorkbenchState::Report);
    }
}
