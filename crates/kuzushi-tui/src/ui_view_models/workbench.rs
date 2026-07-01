//! View-model for the Workbench command center (`ShellView::Workbench`).
//!
//! Pure composition over the existing finding / code / DFD / journey view-models.
//! The renderer and the plain `workbench_lines` path both consume this single
//! model so TTY and scripted output stay in lockstep.

use super::display_text::compact_target_path;
use super::{
    findings_model, has_run_activity, journey_model, journey_phase_segment,
    selected_finding_code_model, selected_finding_detail_model, source_tree_model,
    threat_model_doc, CodePaneModel, FindingDetailModel, FindingsModel, SourceTreeModel,
};
use crate::app::{WorkbenchPane, WorkflowPhase};
use crate::ShellApp;

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
    /// Lit only on real run activity (scan/tool/module-run).
    pub(crate) live: bool,
    /// `組 map 1/4`-style chip, or `None` without a target.
    pub(crate) phase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkbenchCenter {
    pub(crate) title: String,
    pub(crate) body: WorkbenchCenterBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkbenchCenterBody {
    Code(CodePaneModel),
    Dfd {
        /// `Some` when no DFD artifact exists — the pane shows one guidance line.
        empty_hint: Option<&'static str>,
    },
}

/// A command-bar label that maps to an existing shell verb (no new tool paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkbenchHint {
    pub(crate) verb: &'static str,
    pub(crate) label: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchViewModel {
    pub(crate) top_bar: WorkbenchTopBar,
    pub(crate) left: SourceTreeModel,
    pub(crate) center: WorkbenchCenter,
    pub(crate) right_list: FindingsModel,
    pub(crate) right_detail: Option<FindingDetailModel>,
    pub(crate) command_bar_hints: Vec<WorkbenchHint>,
    pub(crate) state: WorkbenchState,
    pub(crate) focus: WorkbenchPane,
}

const COMMAND_BAR_HINTS: [WorkbenchHint; 3] = [
    WorkbenchHint {
        verb: "scan",
        label: "rescan target",
    },
    WorkbenchHint {
        verb: "options",
        label: "tune scanners",
    },
    WorkbenchHint {
        verb: "ask",
        label: "ask the agent",
    },
];

const DFD_EMPTY_HINT: &str =
    "no threat model yet — run `threat-model:build` to map this target's data flows.";

pub(crate) fn workbench_view_model(app: &ShellApp) -> WorkbenchViewModel {
    WorkbenchViewModel {
        top_bar: top_bar_model(app),
        left: source_tree_model(app),
        center: center_model(app),
        right_list: findings_model(app),
        right_detail: selected_finding_detail_model(app),
        command_bar_hints: COMMAND_BAR_HINTS.to_vec(),
        state: workbench_state(app),
        focus: app.workbench_focus,
    }
}

fn top_bar_model(app: &ShellApp) -> WorkbenchTopBar {
    WorkbenchTopBar {
        brand: "Kuzushi",
        project: project_label(app),
        target: target_label(app),
        live: has_run_activity(app),
        phase: phase_chip(app),
    }
}

fn project_label(app: &ShellApp) -> String {
    if app.target.is_some() {
        super::scoped_target_path_label(app)
    } else {
        "no target".to_string()
    }
}

fn target_label(app: &ShellApp) -> String {
    app.focused_module
        .clone()
        .unwrap_or_else(|| "all modules".to_string())
}

fn phase_chip(app: &ShellApp) -> Option<String> {
    let journey = journey_model(app)?;
    Some(journey_phase_segment(journey.current))
}

fn center_model(app: &ShellApp) -> WorkbenchCenter {
    if app.workbench_focus != WorkbenchPane::Center {
        if let Some(center) = code_center_model(app) {
            return center;
        }
    }
    dfd_center_model(app)
}

fn code_center_model(app: &ShellApp) -> Option<WorkbenchCenter> {
    selected_finding_code_model(app).map(|code| WorkbenchCenter {
        title: code.title.clone(),
        body: WorkbenchCenterBody::Code(code),
    })
}

fn dfd_center_model(app: &ShellApp) -> WorkbenchCenter {
    WorkbenchCenter {
        title: "DFD".to_string(),
        body: WorkbenchCenterBody::Dfd {
            empty_hint: (!super::threat_dfd_present(app)).then_some(DFD_EMPTY_HINT),
        },
    }
}

fn workbench_state(app: &ShellApp) -> WorkbenchState {
    derive_state(WorkbenchStateInputs {
        scanning: has_run_activity(app),
        selected: app.selected_finding.is_some(),
        has_findings: !app.findings.is_empty(),
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
    use kuzushi_core::{Finding, Severity, V2Config};

    fn app() -> ShellApp {
        ShellApp::new(V2Config::default(), None)
    }

    fn finding(severity: Severity) -> Finding {
        Finding::new_semgrep("demo.rule", "crates/foo.rs", 12, None, severity, "title")
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
        app.scan = Some(crate::app::ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: std::path::PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        let model = workbench_view_model(&app);
        assert!(model.top_bar.live);
        assert_eq!(model.state, WorkbenchState::Scanning);
    }

    #[test]
    fn first_run_state_with_no_findings_and_no_doc() {
        let model = workbench_view_model(&app());
        assert_eq!(model.state, WorkbenchState::FirstRun);
        assert!(matches!(
            model.center.body,
            WorkbenchCenterBody::Dfd {
                empty_hint: Some(_)
            }
        ));
        assert!(model.left.empty_hint.is_some());
    }

    #[test]
    fn finding_detail_state_when_a_finding_is_selected() {
        let mut app = app();
        app.findings = vec![finding(Severity::High)];
        app.selected_finding = Some(finding(Severity::High));
        let model = workbench_view_model(&app);
        assert_eq!(model.state, WorkbenchState::FindingDetail);
        assert!(model.right_detail.is_some());
        assert!(matches!(model.center.body, WorkbenchCenterBody::Code(_)));
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
            WorkbenchCenterBody::Code(code) => {
                assert!(code.title.contains("F-0002"), "{:?}", code.title);
            }
            WorkbenchCenterBody::Dfd { .. } => panic!("expected code preview"),
        }
    }

    #[test]
    fn center_focus_shows_dfd_even_with_selected_finding() {
        let mut app = app();
        app.findings = vec![finding(Severity::High)];
        app.selected_finding = Some(app.findings[0].clone());
        app.workbench_focus = WorkbenchPane::Center;

        let model = workbench_view_model(&app);

        assert!(matches!(model.center.body, WorkbenchCenterBody::Dfd { .. }));
    }

    fn app_with_findings_cursor(app: &mut ShellApp, first: Finding, second: Finding) {
        app.findings = vec![first.clone(), second];
        app.selected_finding = Some(first);
        app.findings_cursor = 1;
    }

    #[test]
    fn severity_chip_counts_reflect_findings() {
        let mut app = app();
        app.findings = vec![
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::High),
            finding(Severity::Low),
        ];
        let counts = workbench_view_model(&app).right_list.counts;
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 2);
        assert_eq!(counts.low, 1);
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
