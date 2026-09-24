use crate::ui_view_models::PhaseSurfaceId;
use kuzushi_core::findings::TriageAuthor;
use kuzushi_core::{
    Finding, FindingEvidence, OptionScope, OptionTarget, RunSummary, ScanCancellation, Severity,
    StaticProofState, TriageOutcome, TriageVerdict, V2Config,
};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

fn wb_focus(app: &ShellApp) -> crate::ui_view_models::PhaseSurfaceId {
    app.router
        .workbench()
        .focus_for(crate::ui_view_models::active_workbench_page(app))
}
use crate::commands::{shell_command_specs, shell_help_examples, ShellCommandCategory};
use crate::ui_view_models::{
    catalog_model, context_snapshot_relative_path, prompt_text, threat_model_relative_path,
    threat_scope_model_from_doc, threat_story_model_from_doc, threat_stride_rollup_from_doc,
    ui_latest_run_path, ui_run_artifact_relative_path, ui_run_dir, view_status_segment,
    ModuleRunStatusKind, RoutingMode, SeverityTone, ThreatStrideTone,
};

use super::*;

mod activity_reader;
mod keymap_reader;
mod prove_detail_controls;

fn apply_renderer_notice(session: &mut ActivitySession, message: &str) {
    use kuzushi_core::run_lifecycle::{
        DiagnosticLevel, RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemV1, SafeText,
    };
    let item = RunItemEnvelopeV1::new(
        session.run_projection.last_committed_seq + 1,
        RunId::parse(&session.run_id).unwrap(),
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(message),
        },
        session.run_projection.last_event_hash.clone(),
    )
    .unwrap();
    session.apply_run_item(item).unwrap();
}

fn write_lifecycle_notices(target: &std::path::Path, run_id: &str, messages: &[&str]) {
    use kuzushi_core::run_lifecycle::{
        DiagnosticLevel, RunItemId, RunItemRecord, RunItemSource, RunItemV1, RunItemWriter,
        SafeText,
    };
    let writer = RunItemWriter::open(target, run_id, None).unwrap();
    for message in messages {
        writer
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::DiagnosticNotice {
                    level: DiagnosticLevel::Info,
                    message: SafeText::operator_visible(*message),
                },
            ))
            .unwrap();
    }
}

fn write_completed_lifecycle(target: &std::path::Path, run_id: &str, summary: &str) {
    use kuzushi_core::run_lifecycle::{
        RunItemId, RunItemRecord, RunItemSource, RunItemStatus, RunItemV1, RunItemWriter, SafeText,
        WorkflowContinuation,
    };
    let writer = RunItemWriter::open(target, run_id, None).unwrap();
    writer
        .emit_and_flush(RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible(summary),
                cost: kuzushi_core::runtime::RuntimeCostReport::known(
                    kuzushi_core::runtime::RuntimeCost::ZERO,
                ),
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("run completed"),
                },
            },
        ))
        .unwrap();
}

fn press_key(app: &mut ShellApp, key: crossterm::event::KeyEvent) -> bool {
    crate::app::update_and_execute_effects(
        app,
        crate::app::Msg::Term(crate::app::TermEvent::Key(key)),
    )
}

fn submit_shell_line(app: &mut ShellApp, raw: &str) -> bool {
    app.set_input(raw);
    crate::app::update_and_execute_effects(
        app,
        crate::app::Msg::Term(crate::app::TermEvent::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::empty(),
        ))),
    )
}

fn run_command(app: &mut ShellApp, command: crate::commands::ShellCommand) -> bool {
    crate::app::update_and_execute_effects(app, crate::app::Msg::Cmd(command))
}

fn context_snapshot_fixture_path() -> std::path::PathBuf {
    kuzushi_core::context_snapshot_path("")
}

fn target_context_snapshot_path(target: &std::path::Path) -> std::path::PathBuf {
    kuzushi_core::context_snapshot_path(target)
}

#[test]
fn kuzushi_theme_uses_blue_cyan_cockpit_accents() {
    assert_eq!(
        theme::T_ACCENT,
        ratatui::prelude::Color::Rgb(0x7f, 0xb8, 0xff)
    );
    assert_eq!(
        theme::T_LABEL,
        ratatui::prelude::Color::Rgb(0xa6, 0xcd, 0xff)
    );
}

#[test]
fn renders_ink_style_shell_without_box_dashboard() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("RUN"));
    assert!(rendered.contains("artifacts"));
    assert!(rendered.contains("modules"));
    assert!(rendered.contains("kuzushi>"));
    assert!(rendered.contains("Tab complete"));
    assert!(rendered.contains("next"));
    assert!(!rendered.contains("command log"));
    assert!(!rendered.contains("┌"));
    assert!(!rendered.contains("v2"));
}

#[test]
fn retry_gate_card_renders_failed_tasks_and_fix() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_retry = Some(crate::app::PendingRetry {
        tasks: vec![crate::app::FailedPlanningTask {
            task: crate::app::PlanningTaskId::BuildCodePropertyGraph,
            error: "graph build failed".to_string(),
            blocked: vec![crate::app::PlanningTaskId::HuntTaint],
        }],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // The retry section must paint its own card (correct handler index).
    assert!(rendered.contains("RETRY"));
    assert!(rendered.contains("cpg:build"));
    assert!(rendered.contains("graph build failed"));
    assert!(rendered.contains("retry"));
}

fn planning_row_fixture(
    id: crate::app::PlanningTaskId,
    state: crate::app::PlanningArtifactState,
) -> crate::app::PlanningTaskRow {
    crate::app::PlanningTaskRow {
        id,
        label: id.label(),
        tool_name: id.tool_name(),
        artifact_path: std::path::PathBuf::from("/dev/null"),
        artifact_state: state,
        artifact_modified: None,
        model_backed: id.is_model_backed(),
        required_cli: None,
        cli_available: true,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    }
}

#[test]
fn planning_picker_header_names_the_phase_whose_rows_it_shows() {
    // Finishing a phase from Run Focus advances the engagement without
    // rebuilding the checklist. The header must keep naming the phase these
    // rows were built for — the one Enter runs — not the newer ledger phase.
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(110, 44);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    let rows = vec![planning_row_fixture(
        PlanningTaskId::GatherRepoContext,
        PlanningArtifactState::Cached,
    )];
    app.engagement.planning_picker_mut().open_phase_profiled(
        WorkflowPhase::Map,
        rows,
        [PlanningTaskId::GatherRepoContext].into_iter().collect(),
        false,
    );
    app.engagement.set_phase(WorkflowPhase::Scan);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("── MAP ─"),
        "header titles the picker's own phase: {rendered}"
    );
    assert!(
        !rendered.contains("── SCAN ─"),
        "header must not title the advanced engagement phase: {rendered}"
    );
    assert!(
        rendered.contains(PlanningTaskId::GatherRepoContext.tool_name()),
        "Map's rows are the ones on screen: {rendered}"
    );
}

#[test]
fn compact_phase_title_names_the_picker_phase_not_the_advanced_engagement() {
    // A canonical 80x24 terminal renders the compact layout, whose divider is
    // the only phase vocabulary on screen. It must name the phase these rows
    // were built for — the one Enter runs — after Run Focus advanced the ledger.
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    let rows = vec![planning_row_fixture(
        PlanningTaskId::GatherRepoContext,
        PlanningArtifactState::Cached,
    )];
    app.engagement.planning_picker_mut().open_phase_profiled(
        WorkflowPhase::Map,
        rows,
        [PlanningTaskId::GatherRepoContext].into_iter().collect(),
        false,
    );
    app.engagement.set_phase(WorkflowPhase::Scan);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("── MAP ─"),
        "compact divider titles the picker's own phase: {rendered}"
    );
    assert!(
        !rendered.contains("SCAN"),
        "compact divider must not title the advanced engagement phase: {rendered}"
    );
}

#[test]
fn planning_picker_announces_prior_state_and_plain_language_outcomes() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(110, 44);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    app.findings_mut().push(Finding::new_tool(
        "demo",
        "demo.rule",
        "src/lib.rs",
        7,
        None,
        Severity::Medium,
        "prior finding",
    ));
    let rows = vec![
        planning_row_fixture(
            PlanningTaskId::GatherRepoContext,
            PlanningArtifactState::Cached,
        ),
        planning_row_fixture(PlanningTaskId::BuildXRay, PlanningArtifactState::Missing),
    ];
    app.engagement.planning_picker_mut().open_phase_profiled(
        WorkflowPhase::Map,
        rows,
        [PlanningTaskId::GatherRepoContext, PlanningTaskId::BuildXRay]
            .into_iter()
            .collect(),
        false,
    );
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // Prior state is announced up front, with counts the operator can verify.
    assert!(
        rendered.contains("Resuming"),
        "prior-state banner: {rendered}"
    );
    assert!(rendered.contains("Map"), "phase rail shows map: {rendered}");
    assert!(
        rendered.contains("Scan"),
        "phase rail shows Scan: {rendered}"
    );
    assert!(
        rendered.contains("Review"),
        "phase rail shows Review: {rendered}"
    );
    assert!(rendered.contains("‹←"), "rail advertises left: {rendered}");
    assert!(
        rendered.contains("1 Map"),
        "rail numbers phases: {rendered}"
    );
    assert!(rendered.contains("→›"), "rail advertises right: {rendered}");
    assert!(
        rendered.contains("TASKS FOCUS"),
        "focused task pane is explicit: {rendered}"
    );
    assert!(rendered.contains("cached artifact"));
    assert!(rendered.contains("1 finding"));
    // Ambiguous [x]/[~]/[ ] glyphs are gone; outcomes read as words + a legend.
    assert!(rendered.contains("OUTCOME"));
    assert!(rendered.contains("RUN"));
    assert!(rendered.contains("REUSE"));
    assert!(!rendered.contains("[~]"));
    // Enter is spelled out, not left to guesswork.
    assert!(
        rendered.contains("Enter: run 1 new step"),
        "enter summary: {rendered}"
    );
    assert!(
        !rendered.contains("↑/↓/j/k"),
        "planner body should not duplicate footer keybinds: {rendered}"
    );
    assert!(rendered.contains("type a command"), "{rendered}");
    assert!(rendered.contains("↑/↓ moves the picker"), "{rendered}");
    assert!(!rendered.contains("kuzushi>"), "{rendered}");
}

#[test]
fn guided_scan_question_is_hosted_as_the_dominant_body_card() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.begin_guided_scan_questions();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let cockpit_row = banner_row(buffer, "PROJECT CONTEXT").expect("cockpit row");
    let question_row = banner_row(buffer, "STEP 1 OF 4").expect("question row");
    let question_footer_row = banner_row(buffer, "Esc dismiss").expect("question footer row");

    assert!(
        question_row > cockpit_row,
        "question must sit below the guided context strip"
    );
    assert!(
        question_row <= 18,
        "question card should be hosted in the body, not bottom anchored; row was {question_row}"
    );
    assert!(
        question_footer_row < 34,
        "the composer edge belongs to the prompt line when the card is hosted; footer row was {question_footer_row}"
    );
}

#[test]
fn guided_scan_compact_bottom_sheet_keeps_question_visible() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);
    app.begin_guided_scan_questions();
    app.set_success_notice("run", "run receipt · completed · 3 runs");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("No accepted"),
        "question missing: {rendered}"
    );
    assert!(
        rendered.contains("Run recommended"),
        "focused choice missing: {rendered}"
    );
    assert!(
        rendered.contains("NEXT"),
        "cockpit context missing: {rendered}"
    );
    assert!(
        !rendered.contains("run receipt"),
        "stale notice competed with the active question: {rendered}"
    );
}

#[test]
fn planning_picker_options_focus_marks_the_options_pane() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(132, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::BuildStrideThreatModel,
        PlanningArtifactState::Missing,
    )];
    app.engagement.planning_picker_mut().open(
        rows,
        [PlanningTaskId::BuildStrideThreatModel]
            .into_iter()
            .collect(),
    );
    app.engagement
        .planning_picker_mut()
        .set_focus(PickerFocus::OptionsPane);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("OPTION FOCUS"),
        "focused options pane is explicit: {rendered}"
    );
    assert!(
        !rendered.contains("TASKS FOCUS"),
        "inactive task pane should not claim focus: {rendered}"
    );

    app.engagement.planning_picker_mut().set_option_edit(Some(
        crate::app::PlanningOptionEdit::new(
            PlanningTaskId::BuildStrideThreatModel,
            "model",
            "openai:gpt-5.5",
        ),
    ));
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let editing = format!("{:?}", terminal.backend().buffer());
    assert!(editing.contains("EDITING OPTION"), "{editing}");
    assert!(editing.contains("Enter save"), "{editing}");
    assert!(editing.contains("Esc cancel"), "{editing}");
}

#[test]
fn compact_planning_picker_keeps_confirmation_and_controls_visible() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    for (width, height, expected_window) in [(80, 24, "TASKS 1-8/10"), (60, 20, "TASKS 1-6/10")] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let dir = tempfile::tempdir().unwrap();
        app.set_target(Some(dir.path().to_path_buf()));
        app.engagement.set_phase(WorkflowPhase::Map);
        let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
            .into_iter()
            .map(|id| planning_row_fixture(id, PlanningArtifactState::Missing))
            .collect::<Vec<_>>();
        let selected = rows.iter().take(5).map(|row| row.id).collect();
        app.engagement.planning_picker_mut().open(rows, selected);
        app.set_shell_view(ShellView::PlanningPicker);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(expected_window),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Target confirmed:"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Attach reference files"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Focused: Gather repo context"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Enter: run 5 new steps · skip 5 unchecked"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Space outcome"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Enter run"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Esc exit"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            !rendered.contains("tool descriptor missing"),
            "{width}x{height}: {rendered}"
        );
    }
}

#[test]
fn compact_planning_picker_scrolls_to_keep_the_focused_task_legible() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .map(|id| planning_row_fixture(id, PlanningArtifactState::Missing))
        .collect();
    app.engagement
        .planning_picker_mut()
        .open(rows, Default::default());
    app.engagement.planning_picker_mut().set_cursor(8);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TASKS 5-10/10"), "{rendered}");
    assert!(
        rendered.contains("> SKIP     Inventory deps for CVE harvest"),
        "{rendered}"
    );
    assert!(rendered.contains("Enter:"), "{rendered}");
    assert!(rendered.contains("Enter run"), "{rendered}");
}

#[test]
fn ultra_compact_planning_picker_keeps_the_primary_controls_visible() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .map(|id| planning_row_fixture(id, PlanningArtifactState::Missing))
        .collect::<Vec<_>>();
    let selected = rows
        .iter()
        .filter(|row| !row.id.is_inline_action())
        .take(5)
        .map(|row| row.id)
        .collect();
    app.engagement.planning_picker_mut().open(rows, selected);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("Focused: Gather repo context"),
        "{rendered}"
    );
    assert!(rendered.contains("Space outcome"), "{rendered}");
    assert!(rendered.contains("Enter run"), "{rendered}");
    assert!(rendered.contains("Esc"), "{rendered}");
}

#[test]
fn planning_picker_preserves_confirmation_at_common_mid_sizes() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    for (width, height) in [(80, 30), (100, 30)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let dir = tempfile::tempdir().unwrap();
        app.set_target(Some(dir.path().to_path_buf()));
        app.engagement.set_phase(WorkflowPhase::Map);
        let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
            .into_iter()
            .map(|id| planning_row_fixture(id, PlanningArtifactState::Missing))
            .collect::<Vec<_>>();
        let selected = rows
            .iter()
            .filter(|row| !row.id.is_inline_action())
            .take(5)
            .map(|row| row.id)
            .collect();
        app.engagement.planning_picker_mut().open(rows, selected);
        app.set_shell_view(ShellView::PlanningPicker);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("Enter: run 5"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Space outcome"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Enter run"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Esc exit"),
            "{width}x{height}: {rendered}"
        );
    }
}

#[test]
fn option_rich_planning_row_preserves_confirmation_at_100x32() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(100, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = PlanningTaskId::in_phase(WorkflowPhase::Map)
        .into_iter()
        .map(|id| planning_row_fixture(id, PlanningArtifactState::Missing))
        .collect::<Vec<_>>();
    let selected = rows.iter().map(|row| row.id).collect();
    let option_rich = rows
        .iter()
        .position(|row| row.id == PlanningTaskId::BuildThreatModel)
        .unwrap();
    app.engagement.planning_picker_mut().open(rows, selected);
    app.engagement.planning_picker_mut().set_cursor(option_rich);
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Build threat model"), "{rendered}");
    assert!(rendered.contains("Enter: run"), "{rendered}");
    assert!(rendered.contains("Space outcome"), "{rendered}");
    assert!(rendered.contains("Enter run"), "{rendered}");
}

#[test]
fn attach_row_explains_its_inline_action_in_the_wide_detail_pane() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(132, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::AttachFiles,
        PlanningArtifactState::Action,
    )];
    app.engagement
        .planning_picker_mut()
        .open(rows, [PlanningTaskId::AttachFiles].into_iter().collect());
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("inline action — no module runs"),
        "{rendered}"
    );
    assert!(
        rendered.contains("Enter opens the target file picker"),
        "{rendered}"
    );
    assert!(
        rendered.contains("attachments stay rooted to this target"),
        "{rendered}"
    );
    assert!(!rendered.contains("tool descriptor missing"), "{rendered}");
}

#[test]
fn unchecked_attach_row_does_not_promise_that_enter_opens_the_picker() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(132, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::AttachFiles,
        PlanningArtifactState::Action,
    )];
    app.engagement
        .planning_picker_mut()
        .open(rows, Default::default());
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("unchecked inline action"), "{rendered}");
    assert!(
        rendered.contains("Space selects; Enter runs checked plan"),
        "{rendered}"
    );
    assert!(rendered.contains("Space select attach"), "{rendered}");
    assert!(!rendered.contains("Tab pane"), "{rendered}");
}

#[test]
fn blocked_planning_row_names_its_exact_prerequisite_in_focused_detail() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let mut row = planning_row_fixture(
        PlanningTaskId::BuildCodeQlDatabase,
        PlanningArtifactState::Missing,
    );
    row.required_cli = Some("codeql");
    row.cli_available = false;
    app.engagement
        .planning_picker_mut()
        .open(vec![row], Default::default());
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("prerequisite missing"), "{rendered}");
    assert!(rendered.contains("install `codeql` on PATH"), "{rendered}");
    assert!(!rendered.contains("KUZUSHI_*_BIN"), "{rendered}");
}

#[test]
fn planning_picker_pins_operator_attention_to_the_top() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(120, 60);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::GatherRepoContext,
        PlanningArtifactState::Missing,
    )];
    app.engagement.planning_picker_mut().open_phase_profiled(
        WorkflowPhase::Map,
        rows,
        [PlanningTaskId::GatherRepoContext].into_iter().collect(),
        false,
    );
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let header_row = banner_row(buffer, "MAP").expect("phase header row");
    let prompt_row = banner_row(buffer, "type a command").expect("prompt row");

    assert!(
        header_row <= 1,
        "planner should begin at the top on tall terminals; header row was {header_row}"
    );
    assert!(
        prompt_row > header_row,
        "prompt/footer should stay below the attention-first planner content"
    );
}

#[test]
fn planning_picker_revisit_banner_names_cached_artifact_behavior() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::GatherRepoContext,
        PlanningArtifactState::Cached,
    )];
    app.engagement.planning_picker_mut().open(
        rows,
        [PlanningTaskId::GatherRepoContext].into_iter().collect(),
    );
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Revisiting"), "{rendered}");
    assert!(rendered.contains("Space cycles cached work"), "{rendered}");
    assert!(!rendered.contains("Resuming"), "{rendered}");
}

#[test]
fn planning_picker_prompt_focus_renders_live_prompt() {
    let backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let rows = vec![planning_row_fixture(
        PlanningTaskId::GatherRepoContext,
        PlanningArtifactState::Missing,
    )];
    app.engagement
        .planning_picker_mut()
        .open(rows, Default::default());
    app.set_shell_view(ShellView::PlanningPicker);
    app.engagement
        .planning_picker_mut()
        .set_focus(PickerFocus::Prompt);
    app.set_input("help");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("kuzushi>"), "{rendered}");
    assert!(rendered.contains("help"), "{rendered}");
    assert!(!rendered.contains("↑/↓ moves the picker"), "{rendered}");
}

#[test]
fn planning_picker_reuses_cached_artifact_when_rebuild_cli_is_missing() {
    use crate::app::{PlanningArtifactState, PlanningTaskId, WorkflowPhase};

    let backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let dir = tempfile::tempdir().unwrap();
    app.set_target(Some(dir.path().to_path_buf()));
    app.engagement.set_phase(WorkflowPhase::Map);
    let mut row = planning_row_fixture(
        PlanningTaskId::BuildCodeQlDatabase,
        PlanningArtifactState::Cached,
    );
    row.required_cli = Some("codeql");
    row.cli_available = false;
    app.engagement.planning_picker_mut().open(
        vec![row],
        [PlanningTaskId::BuildCodeQlDatabase].into_iter().collect(),
    );
    app.set_shell_view(ShellView::PlanningPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("REUSE"), "{rendered}");
    assert!(rendered.contains("cached"), "{rendered}");
    assert!(rendered.contains("rebuild needs codeql"), "{rendered}");
    assert!(!rendered.contains("blocked — install codeql"), "{rendered}");
}

#[test]
fn plain_retry_gate_explains_y_n_intercept() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_retry = Some(crate::app::PendingRetry {
        tasks: vec![crate::app::FailedPlanningTask {
            task: crate::app::PlanningTaskId::BuildCodePropertyGraph,
            error: "graph build failed".to_string(),
            blocked: vec![crate::app::PlanningTaskId::HuntTaint],
        }],
    });

    let rendered = render_plain_app(&app, 100);

    assert!(rendered.contains("RETRY"));
    assert!(rendered.contains("y/Enter retry"));
    assert!(rendered.contains("n/Esc skip"));
    assert!(rendered.contains("cpg:build"));
    assert!(rendered.contains("graph build failed"));
}

#[test]
fn compact_alias_uses_kz_prompt_brand() {
    assert_eq!(prompt_text("kz", RoutingMode::Shell, None), "kz> ");
    assert_eq!(
        prompt_text("kz", RoutingMode::Module, Some("sast")),
        "kz/sast> "
    );
    assert_eq!(
        prompt_text("kz", RoutingMode::Run, Some("sast")),
        "kz/sast/run> "
    );
}

#[test]
fn home_first_run_state_names_real_artifact_commands() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("RUN"));
    assert!(rendered.contains("artifacts"));
    assert!(rendered.contains("target ."));
    assert!(rendered.contains("next"));
    assert!(rendered.contains("findings"));
    assert!(rendered.contains("modules"));
    assert!(rendered.contains("quickstart"));
    assert!(rendered.find("target .").unwrap() < rendered.find("next").unwrap());
    assert!(!rendered.contains("./repo"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn home_view_renders_latest_run_artifact_rail() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(run_dir.join("run.json"), r#"{"status":"completed"}"#).unwrap();
    std::fs::write(run_dir.join("context.json"), r#"{"languages":["rust"]}"#).unwrap();
    std::fs::write(run_dir.join("findings.json"), r#"{"status": "skipped"}"#).unwrap();
    std::fs::write(
        run_dir.join("attack-surface.json"),
        serde_json::json!({
            "status": "partial",
            "summary": {
                "highRisk": 2,
                "maxRiskScore": 100,
                "byRiskTier": {"critical": 1, "high": 1}
            },
            "surfaces": [{
                "framework": "Spring",
                "title": "Command execution boundary",
                "risk": {"tier": "critical"}
            }, {
                "framework": "Next.js",
                "title": "POST /api/session",
                "risk": {"tier": "medium"}
            }, {
                "framework": "Rails",
                "title": "Background job boundary",
                "risk": {"tier": "high"}
            }]
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(run_dir.join("threat-model.json"), r#"{"status":"failed"}"#).unwrap();
    std::fs::write(
        run_dir.join("artifacts.json"),
        r#"{"runId":"run-1","artifacts":[]}"#,
    )
    .unwrap();
    std::fs::write(run_dir.join("failures.json"), r#"{"status":"failed"}"#).unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_shell_view(ShellView::Home);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("HOME"));
    assert!(rendered.contains("run-1"));
    assert!(rendered.contains("completed"));
    assert!(rendered.contains("SURFACE"));
    assert!(rendered.contains("2 high/critical"));
    assert!(rendered.contains("critical=1"));
    assert!(rendered.contains("frameworks Next.js=1, Rails=1, Spring=1"));
    assert!(rendered.contains("✓"));
    assert!(rendered.contains("recorded"));
    assert!(rendered.contains("failures"));
    assert!(rendered.contains("report"));
    assert!(rendered.contains("manifest"));
    assert!(rendered.contains("⚠"));
    assert!(rendered.contains("■"));
}

#[test]
fn catalog_default_is_grouped_at_normal_width() {
    let backend = TestBackend::new(120, 60);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CAPABILITIES"));
    assert!(rendered.contains("▸ NEXT"));
    assert!(rendered.contains("MAP"));
    assert!(rendered.contains("PRIMARY"));
    assert!(rendered.contains("Quick map"));
    assert!(rendered.contains("Deep threat map"));
    assert!(rendered.contains("Import recon"));
    assert!(!rendered.contains("EXPERT"));
}

#[test]
fn catalog_default_keeps_quickstart_fallback_on_tight_width() {
    let backend = TestBackend::new(80, 16);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CAPABILITIES"));
    assert!(rendered.contains("MAP"));
    assert!(rendered.contains("Quick map"));
    assert!(rendered.contains("Deep threat map"));
    assert!(rendered.contains("▸ Quick map"));
    assert!(!rendered.contains("agentic-sast"));
}

#[test]
fn contextual_catalog_keeps_every_cursor_visible_across_compact_sizes() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    for (width, height) in [(80, 24), (60, 20), (40, 12)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_viewport(crate::app::TerminalViewport::new(width, height));
        app.set_shell_view(ShellView::Workbench);

        assert!(submit_shell_line(&mut app, "modules"));
        assert_eq!(app.shell_view(), ShellView::Catalog);
        assert_eq!(app.router.overlay_origin(), Some(ShellView::Workbench));
        app.set_input_mode(crate::InputMode::Navigate);

        let labels = catalog_model(&app)
            .groups
            .iter()
            .flat_map(|group| group.rows.iter().map(|row| row.cells[0].clone()))
            .collect::<Vec<_>>();
        assert_eq!(labels.len(), 3);

        for (cursor, selected_label) in labels.iter().enumerate() {
            terminal.draw(|frame| render_app(frame, &app)).unwrap();
            let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

            assert!(
                rendered.contains("CAPABILITIES"),
                "{width}x{height} cursor {cursor}: {rendered}"
            );
            assert!(
                rendered.contains(selected_label),
                "{width}x{height} hid selected {selected_label}: {rendered}"
            );
            assert!(
                rendered.contains(&format!("{}/{}", cursor + 1, labels.len())),
                "{width}x{height} omitted cursor position: {rendered}"
            );
            assert_eq!(
                rendered.matches('▸').count(),
                1,
                "{width}x{height} must expose exactly one focused action: {rendered}"
            );
            assert!(
                !rendered.contains("build context & analysis artifacts"),
                "{width}x{height} leaked the Workbench origin: {rendered}"
            );
            if width == 80 {
                for label in &labels {
                    assert!(
                        rendered.contains(label),
                        "80x24 should show every default action: {rendered}"
                    );
                }
            }

            if cursor + 1 < labels.len() {
                assert!(press_key(
                    &mut app,
                    KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)
                ));
            }
        }
    }
}

#[test]
fn quickstart_follows_the_live_target_first_operator_path() {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Quickstart);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = (0..30)
        .map(|y| buffer_row_text(buffer, 100, y))
        .collect::<Vec<_>>()
        .join("\n");

    for expected in [
        "Operator path",
        "target .",
        "doctor",
        "check scanners",
        "model",
        "stay offline",
        "next",
        "Space toggles tasks",
        "findings",
        "open F-0001",
        "verify F-0001",
        "findings export",
        "write a shareable report",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected}: {rendered}"
        );
    }
    assert!(rendered.find("1. target .").unwrap() < rendered.find("2. doctor").unwrap());
    assert!(rendered.find("2. doctor").unwrap() < rendered.find("3. model").unwrap());
    assert!(rendered.find("3. model").unwrap() < rendered.find("4. next").unwrap());
    assert!(rendered.find("4. next").unwrap() < rendered.find("5. findings").unwrap());
    assert!(!rendered.contains("run from your terminal, not here"));
    for y in 0..30 {
        let row = buffer_row_text(buffer, 100, y);
        assert!(
            row.chars().count() <= 100,
            "row exceeded 100 columns: {row:?}"
        );
    }
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_actionable_empty_states_at_80_columns() {
    // Each empty-state surface advertises a concrete next step,
    // matching `design/mockups/empty-states.jsx::panel` (`∅` glyph
    // + label + indented muted explanation + `▸` CTA rows).
    for (view, expected) in [
        (ShellView::Runs, "no run timeline entries"),
        (ShellView::Workspace, "no workspace selected"),
    ] {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let runs_target = tempfile::tempdir().unwrap();
        let is_runs = matches!(view, ShellView::Runs);
        app.set_shell_view(view);
        if is_runs {
            app.set_target(Some(runs_target.path().to_path_buf()));
        }

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(expected),
            "missing {expected} in {rendered}"
        );
        if is_runs {
            assert!(rendered.contains(".kuzushi/v3/runs/<id>"), "{rendered}");
        }
        // These line-based empty states must stay free of nested boxes (the
        // bordered phase Workbench is the only box-drawing primary surface).
        assert!(!rendered.contains("┌"), "{expected} drew a box");
    }
}

#[test]
fn renders_long_prompt_on_single_row() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("full ./a/very/long/path/that/should/not/wrap");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("kuzushi>"));
    assert!(!rendered.contains("prompt"));
}

#[test]
fn prompt_renders_completion_preview_suffix() {
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("/he");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let row = buffer_row_text(terminal.backend().buffer(), 80, 11);

    assert!(row.contains("/he"), "{row}");
    assert!(row.contains("lp"), "{row}");
}

#[test]
fn prompt_renders_empty_placeholder() {
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let app = ShellApp::new(V2Config::default(), None);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let row = buffer_row_text(terminal.backend().buffer(), 80, 11);

    assert!(row.contains("type help or press Tab"), "{row}");
}

#[test]
fn prompt_renders_fuzzy_completion_candidate() {
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    // "fnd" alone now also fuzzy-matches the shorter `find` verb, so use a
    // suffix ("gs") that only the `findings*` family contains to keep this
    // test unambiguous.
    app.set_input("fndgs");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let row = buffer_row_text(terminal.backend().buffer(), 80, 11);

    assert!(row.contains("fndgs"), "{row}");
    assert!(row.contains("findings"), "{row}");
}

#[test]
fn completion_remains_visible_and_explained_at_minimum_size() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input("qu");
    app.apply_completion();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    assert!(rendered.contains("Tab cycle"), "{rendered}");
    assert!(rendered.contains("Enter select"), "{rendered}");
    assert!(rendered.contains("▶ quickstart"), "{rendered}");
    assert!(rendered.contains("Esc restore"), "{rendered}");
}

#[test]
fn keeps_command_log_directly_above_bottom_prompt_at_80_columns() {
    let backend = TestBackend::new(80, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log(
        "error",
        "scanner failed while reading src/really/long/path/that/must/not_overlap.rs",
    );
    app.log(
        "result",
        "next action: inspect configuration and rerun scan with a narrower target",
    );
    app.set_input("run sast:scan {\"severity\":[\"high\"],\"triage\":true}");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let prompt_row = buffer_row_text(buffer, 80, 11);
    let log_row = buffer_row_text(buffer, 80, 10);

    assert!(prompt_row.trim_start().starts_with("kuzushi>"));
    assert!(prompt_row.contains("triage"));
    assert!(!prompt_row.contains("result"));
    assert!(log_row.contains("result"));
    assert!(!log_row.contains("kuzushi>"));
    assert!(!format!("{:?}", buffer).contains("┌"));
}

#[test]
fn renders_exit_commands_before_closing() {
    for command in ["/exit", "exit"] {
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        submit_shell_line(&mut app, command);
        assert!(app.should_quit(), "{command} should request shell shutdown");

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let exit_row = buffer_row_text(buffer, 80, 10);
        let prompt_row = buffer_row_text(buffer, 80, 11);

        assert!(exit_row.contains("exit requested; closing shell"));
        assert!(prompt_row.trim_start().starts_with("kuzushi>"));
    }
}

#[test]
fn replay_and_trace_surfaces_reuse_current_finding_aliases() {
    for view in [ShellView::Replay, ShellView::Trace] {
        let backend = TestBackend::new(80, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.replay_mut().open("run-1");
        app.router.trace_mut().open("run-1");
        let mut finding =
            Finding::new_semgrep("demo.rule", "src/app.ts", 8, None, Severity::High, "sink");
        finding.fingerprint = "aaaa1111".to_string();
        *app.findings_mut() = vec![finding];
        app.set_shell_view(view);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("ALIASES"), "{view:?}: {rendered}");
        assert!(rendered.contains("F-0001"), "{view:?}: {rendered}");
        assert!(rendered.contains("aaaa1111"), "{view:?}: {rendered}");
    }
}

#[test]
fn renders_threat_view_navigation() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Stride);
    app.set_shell_view(ShellView::Threat);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("STRIDE"));
    assert!(rendered.contains("select a target before loading threat-model artifacts"));
}

#[test]
fn threat_model_picker_has_tty_and_plain_content_parity() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let scope =
        kuzushi_core::capabilities::threat_model::current_scope_ref_for_path(temp.path(), ".")
            .unwrap()
            .unwrap();
    let document = serde_json::json!({
        "version": "2.0",
        "methodology": "pasta",
        "dfd": {"nodes": [{"id": "app"}], "flows": [], "trustBoundaries": []},
        "threats": [],
        "summary": {},
        "verification": {"verdict": "verified"}
    });
    kuzushi_core::capabilities::threat_model::commit_threat_model_revision(
        temp.path(),
        &document,
        kuzushi_core::capabilities::threat_model::ThreatModelCommit {
            model_id: None,
            new_model: false,
            label: "Root PASTA".to_string(),
            scope,
            methodology: "pasta".to_string(),
            source: kuzushi_core::capabilities::threat_model::ThreatModelRevisionSource::Build,
            source_revision_id: None,
            run_id: None,
            activate: Some(true),
            actor: "test".to_string(),
        },
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.router.threat_mut().open(ThreatView::Models);
    app.set_shell_view(ShellView::Threat);
    app.hydrate_active_view_blocking();

    let backend = TestBackend::new(132, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let tty = format!("{:?}", terminal.backend().buffer());
    let plain = render_plain_app(&app, 132);

    for text in ["Root PASTA", "pasta", "verified", "m next · M previous"] {
        assert!(tty.contains(text), "TTY missing {text:?}: {tty}");
        assert!(plain.contains(text), "plain missing {text:?}: {plain}");
    }
}

#[test]
fn scan_batch_config_has_tty_and_plain_content_parity() {
    let target = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.router.campaign_mut().batch_scan_config =
        Some(crate::app::BatchScanConfig::load(target.path(), None));
    app.set_shell_view(ShellView::Campaign);

    let backend = TestBackend::new(132, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let tty = format!("{:?}", terminal.backend().buffer());
    let plain = render_plain_app(&app, 132);

    for text in [
        "SCAN BATCH",
        "Scan trials",
        "requested 1",
        "using 1",
        "cost not estimated",
        "start this batch in the background",
    ] {
        assert!(tty.contains(text), "TTY missing {text:?}: {tty}");
        assert!(plain.contains(text), "plain missing {text:?}: {plain}");
    }
}

#[test]
fn scan_batch_results_have_tty_and_plain_content_parity() {
    use kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot;
    use kuzushi_core::findings::{BatchOccurrenceReport, BatchOccurrenceRow, IdentityFoldPolicy};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    let deck = app.router.campaign_mut();
    deck.detail = true;
    deck.active_batch_id = Some("batch-parity".to_string());
    deck.campaigns = vec![CampaignSnapshot {
        campaign_id: "batch-parity".to_string(),
        kind: Some("scan-batch".to_string()),
        requested_workers: Some(4),
        effective_workers: Some(2),
        parallel_safety_reason: Some("shared read".to_string()),
        tool: Some("sast:scan".to_string()),
        created_at_ms: None,
        paused_until_ms: None,
        budget_usd: None,
        job_budget_usd: None,
        fill_gaps: false,
        skipped_covered_cells: None,
        total_cost_usd: 0.0,
        provider_spend_unresolved: false,
        jobs: Vec::new(),
    }];
    deck.active_batch_report = Some(BatchOccurrenceReport {
        schema_version: 1,
        batch_id: "batch-parity".to_string(),
        equivalence_key: "eq-parity".to_string(),
        identity_fold: IdentityFoldPolicy::Safe,
        planned: 4,
        completed: 3,
        failed: 1,
        pending: 0,
        gate: None,
        trials: Vec::new(),
        rows: vec![BatchOccurrenceRow {
            fold_key: "finding-parity".to_string(),
            identity_id: None,
            identity_basis: None,
            seen: 2,
            completed: 3,
            planned: 4,
            failed: 1,
            severities: vec!["high".to_string()],
            locations: vec!["src/auth.rs:7".to_string()],
            titles: vec!["auth bypass".to_string()],
            fingerprints: vec!["finding-parity".to_string()],
            run_ids: vec!["run-1".to_string()],
            representative_fingerprint: "finding-parity".to_string(),
            representative_title: "auth bypass".to_string(),
            representative_severity: "high".to_string(),
            representative_location: "src/auth.rs:7".to_string(),
        }],
    });

    let backend = TestBackend::new(132, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let tty = format!("{:?}", terminal.backend().buffer());
    let plain = render_plain_app(&app, 132);
    for text in [
        "BATCH batch-parity",
        "BATCH OCCURRENCE",
        "seen 2 / completed 3",
        "runs run-1",
    ] {
        assert!(tty.contains(text), "TTY missing {text:?}: {tty}");
        assert!(plain.contains(text), "plain missing {text:?}: {plain}");
    }
}

#[test]
fn renders_pending_threat_patch_card() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_threat_patch(crate::app::ThreatPatch {
        goal: "regen".to_string(),
        summary: "add admin trust zone".to_string(),
        patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
        unsupported: vec!["manual review required".to_string()],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT PATCH"));
    assert!(rendered.contains("add admin trust zone"));
    assert!(rendered.contains("1 top-level key"));
    assert!(rendered.contains("/threats apply"));
    assert!(rendered.contains("/threats reject"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_expanded_catalog_readably_on_narrow_terminal() {
    let backend = TestBackend::new(58, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, crate::commands::ShellCommand::Modules);
    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('e'),
            crossterm::event::KeyModifiers::empty(),
        ),
    );
    *app.findings_mut() = (0..82)
        .map(|index| {
            Finding::new_semgrep(
                format!("demo.rule.{index}"),
                "src/app.ts",
                index + 1,
                None,
                Severity::Medium,
                "demo finding",
            )
        })
        .collect();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("82 findings"));
    assert!(rendered.contains("Repository"));
    assert!(rendered.contains("EXPERT"));
    assert!(!rendered.contains("module context-lite"));
    assert!(!rendered.contains("command log"));
}

#[test]
fn expanded_catalog_uses_design_sections_without_dag_column() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, crate::commands::ShellCommand::Modules);
    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('e'),
            crossterm::event::KeyModifiers::empty(),
        ),
    );

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CAPABILITIES"));
    assert!(rendered.contains("▸ NEXT"));
    assert!(rendered.contains("EXPERT"));
    assert!(rendered.contains("Repository context"));
    assert!(!rendered.contains("dag"));
    assert!(!rendered.contains("DAG"));
}

#[test]
fn catalog_next_hint_steers_through_context_then_findings() {
    let mut app = ShellApp::new(V2Config::default(), None);

    // Default fresh app: no context snapshot built.
    assert!(
        catalog_model(&app)
            .collapsed
            .next_hint
            .contains("context build"),
        "fresh app should suggest context build"
    );

    // After context exists but no findings: first-finding scan hint.
    app.domain_mut().context_view_mut().exists = true;
    app.domain_mut().context_view_mut().freshness =
        Some(kuzushi_core::context::ContextSnapshotFreshness::Current);
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(
        hint.contains("First finding") || hint.contains("scan"),
        "ctx-built no-findings should suggest scanning, got: {hint}"
    );

    // With non-critical findings: drill-in suggestion.
    let medium = Finding::new_semgrep("demo.rule", "src/a.rs", 1, None, Severity::Medium, "x");
    *app.findings_mut() = vec![medium];
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(hint.contains("findings"), "got: {hint}");
    assert!(hint.contains("next"), "got: {hint}");

    // With a critical finding: open-by-alias suggestion.
    let critical = Finding::new_semgrep("demo.crit", "src/b.rs", 2, None, Severity::Critical, "y");
    app.findings_mut().push(critical);
    let hint = catalog_model(&app).collapsed.next_hint;
    assert!(hint.contains("open F-"), "got: {hint}");
}

#[test]
fn module_playbooks_name_supported_run_and_scan_commands() {
    let cases = [
        ("context", "context build", "run build"),
        ("threat-model", "threats regen", "threats build"),
        (
            "sast",
            "next opens guided Scan",
            "scan runs configured scanners",
        ),
        ("cargo-audit", "RustSec advisories", "tool-specific options"),
        (
            "govulncheck",
            "Go reachable vulnerabilities",
            "tool-specific options",
        ),
        ("agentic-sast", "run agentic-sast:scan", "run scan"),
    ];
    for (module, required, stale) in cases {
        let primary_tool = match module {
            "context" => "context:build",
            "threat-model" => "threat-model:build",
            "sast" => "sast:scan",
            "cargo-audit" => "cargo-audit:scan",
            "govulncheck" => "govulncheck:scan",
            "agentic-sast" => "agentic-sast:scan",
            _ => "demo:tool",
        };
        let text = module_playbook_lines(module, primary_tool, 120)
            .into_iter()
            .map(|line| line_text(&line))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            text.contains(required),
            "{module} missing {required}: {text}"
        );
        assert!(
            !text.contains(stale),
            "{module} still shows {stale}: {text}"
        );
        assert!(
            text.contains(&format!("dispatches {primary_tool}")),
            "{module} does not explain run . resolution: {text}"
        );
        assert!(
            text.contains("terminal: kuzushi --target . run"),
            "{module} does not distinguish terminal run syntax: {text}"
        );
        assert!(
            text.contains("options .") || text.contains("options sast:scan"),
            "{module} does not point at the options view: {text}"
        );
        if module == "sast" {
            assert!(
                text.contains("options sast:scan"),
                "{module} does not name scan tuning command: {text}"
            );
            assert!(
                text.contains(".kuzushi/v3/index.sqlite3"),
                "{module} does not name the findings DB artifact: {text}"
            );
        }
        if module == "context" {
            assert!(
                text.contains(context_snapshot_relative_path()),
                "{module} does not name the shared context snapshot label: {text}"
            );
        }
        if module == "threat-model" {
            assert!(
                text.contains(&threat_model_relative_path()),
                "{module} does not name the shared threat-model label: {text}"
            );
        }
    }

    let codeql_text = module_playbook_lines("codeql", "codeql:scan", 120)
        .into_iter()
        .map(|line| line_text(&line))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        codeql_text.contains(".kuzushi/v3/index.sqlite3 and optional SARIF"),
        "codeql does not name findings DB plus optional SARIF: {codeql_text}"
    );
}

#[test]
fn spinner_cycles_through_six_frames_by_log_length() {
    let frames: Vec<&str> = (0..12)
        .map(|tick| run_state_glyph(ModuleRunStatusKind::Running, tick))
        .collect();
    // First 6 ticks cover all 6 frames
    let unique: std::collections::BTreeSet<&&str> = frames.iter().take(6).collect();
    assert_eq!(
        unique.len(),
        6,
        "first 6 frames should be unique: {frames:?}"
    );
    // Frame at tick N == frame at tick N+6 (cycle period)
    for tick in 0..6 {
        assert_eq!(
            frames[tick],
            frames[tick + 6],
            "spinner should repeat every 6 ticks"
        );
    }
}

#[test]
fn spinner_shows_static_glyph_when_scan_idle_or_done() {
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Idle, 0), "●");
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Idle, 99), "●");
    assert_eq!(
        run_state_glyph(ModuleRunStatusKind::Running, 0),
        SPINNER_FRAMES[0]
    );
    assert_eq!(run_state_glyph(ModuleRunStatusKind::Done, 4), "✓");
}

#[test]
fn module_run_body_ends_with_streaming_cursor_when_scan_active() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-abc".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "scanning".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::ModuleRun);
    let area = Rect::new(0, 0, 120, 30);
    let lines = module_run_lines(&app, area);
    let last = lines.last().expect("expected non-empty body");
    let last_text: String = last.spans.iter().map(|s| s.content.as_ref()).collect();
    // The cursor line is " " + a single styled-block " ", so two visible cells.
    assert_eq!(
        last_text, "  ",
        "expected streaming cursor line at end while scan running, got {last_text:?}"
    );
    // Sanity: confirm a styled span with primary bg exists on that line.
    let has_inverse = last
        .spans
        .iter()
        .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
    assert!(
        has_inverse,
        "streaming cursor should be a styled background cell"
    );
}

#[test]
fn module_run_body_omits_streaming_cursor_when_idle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModuleRun);
    let area = Rect::new(0, 0, 120, 30);
    let lines = module_run_lines(&app, area);
    // No scan → no streaming cursor expected.
    for line in &lines {
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        let has_cursor = line
            .spans
            .iter()
            .any(|sp| sp.style.bg.is_some() && sp.content.as_ref() == " ");
        assert!(
            !has_cursor || text.trim() != "",
            "unexpected streaming cursor while idle: {text:?}"
        );
    }
}

#[test]
fn module_run_findings_preview_uses_projected_finding_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModuleRun);
    let mut triaged = Finding::new_semgrep(
        "demo.sql",
        "src/search.ts",
        12,
        Some(14),
        Severity::High,
        "SQL injection in search",
    );
    triaged.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 0.91,
        rationale: "source and sink are linked".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    *app.findings_mut() = vec![
        triaged,
        Finding::new_tool(
            "codeql",
            "js/path-injection",
            "src/files.ts",
            22,
            None,
            Severity::Medium,
            "Path traversal candidate",
        ),
    ];

    let rendered = module_run_lines(&app, Rect::new(0, 0, 120, 40))
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("FINDINGS · 1 TRIAGED · 1 PENDING"));
    assert!(rendered.contains("SQL injection in search"));
    assert!(rendered.contains("src/search.ts:12-14"));
}

#[test]
fn recent_module_activity_uses_recon_snapshot_when_present() {
    use crate::app::ReconSnapshot;
    use kuzushi_core::{ReconHost, ReconService};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().set_recon_snapshot(ReconSnapshot {
        hosts: vec![ReconHost {
            id: "h1".to_string(),
            workspace_id: "ws".to_string(),
            address: "192.0.2.10".to_string(),
            hostname: Some("acme-checkout.com".to_string()),
            state: "alive".to_string(),
        }],
        services: vec![ReconService {
            id: "s1".to_string(),
            host_id: "h1".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            name: Some("https".to_string()),
            banner: Some("nginx/1.24 · TLS1.3".to_string()),
            state: "open".to_string(),
        }],
        notes: Vec::new(),
        last_tool: Some("recon:nmap".to_string()),
        last_target: Some("acme-checkout.com".to_string()),
    });

    let lines = recent_module_activity_lines(&app, "recon", 8);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("acme-checkout.com"),
        "expected snapshot host in output, got:\n{rendered}"
    );
    assert!(
        rendered.contains("443"),
        "expected snapshot port 443 in output, got:\n{rendered}"
    );
    assert!(
        rendered.contains("nginx/1.24"),
        "expected snapshot banner in output, got:\n{rendered}"
    );
}

#[test]
fn compact_recon_module_page_down_reaches_recent_evidence() {
    use crate::app::ReconSnapshot;
    use kuzushi_core::{ReconHost, ReconService};

    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("recon".to_string()));
    app.set_shell_view(ShellView::Module);
    app.domain_mut().set_recon_snapshot(ReconSnapshot {
        hosts: vec![ReconHost {
            id: "h1".to_string(),
            workspace_id: "ws".to_string(),
            address: "192.0.2.10".to_string(),
            hostname: Some("compact-recon.example".to_string()),
            state: "alive".to_string(),
        }],
        services: vec![ReconService {
            id: "s1".to_string(),
            host_id: "h1".to_string(),
            port: 443,
            proto: "tcp".to_string(),
            name: Some("https".to_string()),
            banner: Some("nginx/1.24".to_string()),
            state: "open".to_string(),
        }],
        notes: Vec::new(),
        last_tool: Some("recon:import-httpx".to_string()),
        last_target: Some("compact-recon.example".to_string()),
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let first_page = format!("{:?}", terminal.backend().buffer());
    assert!(
        !first_page.contains("RECENT RECON ACTIVITY"),
        "{first_page}"
    );

    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::empty(),
        ),
    );
    let mut second_page = String::new();
    for _ in 0..4 {
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        second_page = format!("{:?}", terminal.backend().buffer());
        if second_page.contains("ALIASES") {
            break;
        }
        press_key(
            &mut app,
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::PageDown,
                crossterm::event::KeyModifiers::empty(),
            ),
        );
    }
    assert!(
        second_page.contains("RECENT RECON ACTIVITY"),
        "{second_page}"
    );
    assert!(
        second_page.contains("compact-recon.example"),
        "{second_page}"
    );
}

#[test]
fn recent_module_activity_falls_back_to_log_when_no_snapshot() {
    // No snapshot is populated → renderer must keep falling back to the
    // legacy `app.log` grep, which is the pre-snapshot behaviour.
    let mut app = ShellApp::new(V2Config::default(), None);
    // Inject a recon-shaped log line that would be picked up by
    // `recent_module_log` filter (prefix == "result", body contains "recon").
    app.log(
        "result",
        "recon:nmap discovered 1 host and 2 open services for 192.0.2.10",
    );

    let lines = recent_module_activity_lines(&app, "recon", 8);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("recon:nmap discovered 1 host"),
        "expected fallback log-grep line in output, got:\n{rendered}"
    );
}

#[test]
fn sast_progress_bars_use_scan_progress_per_task_when_present() {
    use kuzushi_core::ScanProgress;
    use std::collections::BTreeMap;

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::ModuleRun);
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-real-progress".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "scanning".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));

    let mut per_task = BTreeMap::new();
    per_task.insert("agentic-sast".to_string(), (87usize, 120usize));
    per_task.insert("semgrep".to_string(), (612usize, 612usize));
    app.domain_mut().set_scan_progress(ScanProgress {
        total: 732,
        done: 699,
        current_tool: Some("semgrep".to_string()),
        current_target: Some("./demo".to_string()),
        per_task,
    });

    let area = Rect::new(0, 0, 120, 40);
    let lines = module_run_lines(&app, area);
    let rendered: String = lines
        .iter()
        .flat_map(|line| line.spans.iter().map(|sp| sp.content.as_ref()))
        .collect::<Vec<_>>()
        .join("");

    assert!(
        rendered.contains("612/612"),
        "expected real semgrep done count, got:\n{rendered}"
    );
    assert!(
        rendered.contains("87/120"),
        "expected real agentic-sast progress count, got:\n{rendered}"
    );
    assert!(
        rendered.contains("semgrep"),
        "expected semgrep label in progress bar, got:\n{rendered}"
    );
    assert!(
        rendered.contains("agentic-sast"),
        "expected agentic-sast label in progress bar, got:\n{rendered}"
    );
}

#[test]
fn threat_story_model_from_doc_sorts_by_impact_severity() {
    let doc = serde_json::json!({
        "threats": [
            {"id": "T-001", "title": "low risk",  "impact": "low",      "category": "spoofing",  "attackVector": "vec1"},
            {"id": "T-002", "title": "critical bug", "impact": "critical","category": "tampering","attackVector": "vec2",
             "affectedFiles": [{"filePath": "src/api.rs", "startLine": 42}]},
            {"id": "T-003", "title": "high issue", "impact": "high",     "category": "elevation_of_privilege"}
        ]
    });
    let model = threat_story_model_from_doc(&doc).expect("non-empty stories");
    assert_eq!(model.header, "ATTACKER STORIES · 3");
    assert_eq!(model.rows.len(), 3);
    assert_eq!(model.rows[0].cells[0], "T-002");
    assert_eq!(model.rows[0].cells[1], "CRITICAL");
    assert_eq!(model.rows[0].details[1].value, "src/api.rs:42");
    assert_eq!(model.rows[1].cells[0], "T-003");
    assert_eq!(model.rows[1].cells[1], "HIGH");
    assert_eq!(model.rows[2].cells[0], "T-001");
}

#[test]
fn threat_scope_model_from_doc_groups_by_impact() {
    let doc = serde_json::json!({
        "threats": [
            {"title": "a", "impact": "critical"},
            {"title": "b", "impact": "high"},
            {"title": "c", "impact": "high"},
            {"title": "e", "impact": "high"},
            {"title": "f", "impact": "high"},
            {"title": "g", "impact": "high"},
            {"title": "d", "impact": "medium"}
        ]
    });
    let model = threat_scope_model_from_doc(&doc).expect("non-empty");
    let buckets = &model.buckets;
    assert_eq!(model.header, "SCOPE · 7 issues");
    assert_eq!(buckets.len(), 3);
    assert_eq!(buckets[0].header, "CRITICAL · 1");
    assert_eq!(buckets[0].item_count, 1);
    assert_eq!(buckets[1].header, "HIGH · 5");
    assert_eq!(buckets[1].item_count, 5);
    assert_eq!(buckets[1].visible_items.len(), 4);
    assert_eq!(buckets[1].overflow_label.as_deref(), Some("… 1 more"));
    assert_eq!(buckets[2].header, "MEDIUM · 1");
    assert_eq!(buckets[2].item_count, 1);
}

#[test]
fn threats_stories_view_without_a_target_names_the_targetless_state() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Stories);
    app.set_shell_view(ShellView::Threat);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("ATTACKER STORIES"));
    assert!(rendered.contains("select a target before loading threat-model artifacts"));
    // No invented story may read as target reality.
    assert!(!rendered.contains("order_id concatenation"));
    assert!(!rendered.contains("apps/api/orders.rs"));
}

#[test]
fn threats_scope_view_without_a_target_names_the_targetless_state() {
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Scope);
    app.set_shell_view(ShellView::Threat);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SCOPE"));
    assert!(rendered.contains("select a target before loading threat-model artifacts"));
    // No invented bucket count or item may read as target reality.
    assert!(!rendered.contains("SCOPE · 11 ISSUES"), "{rendered}");
    assert!(!rendered.contains("CRITICAL · 2"), "{rendered}");
    assert!(!rendered.contains("order_id concatenation"), "{rendered}");
}

#[test]
fn threat_stride_rollup_from_doc_returns_none_on_empty_or_missing_threats() {
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({})).is_none());
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({"threats": []})).is_none());
    assert!(threat_stride_rollup_from_doc(&serde_json::json!({"threats": null})).is_none());
}

#[test]
fn threat_stride_rollup_from_doc_normalizes_underscored_categories() {
    let doc = serde_json::json!({
        "threats": [
            {"category": "denial_of_service",        "title": "ddos",  "impact": "medium"},
            {"category": "elevation_of_privilege",   "title": "sudo bypass", "impact": "critical"},
        ]
    });
    let rollup = threat_stride_rollup_from_doc(&doc).expect("rollup should accept underscored");
    let dos = &rollup.rows[4];
    assert_eq!(dos.cells[0], "D");
    assert_eq!(dos.cells[2], "1");
    let elev = &rollup.rows[5];
    assert_eq!(elev.cells[0], "E");
    assert_eq!(elev.cells[2], "1");
    assert_eq!(elev.tone, ThreatStrideTone::Critical);
}

#[test]
fn threats_summary_view_is_review_first_without_fake_observations() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(tmp.path()).unwrap();
    kuzushi_core::save_persistent_threat_model(
        tmp.path(),
        &serde_json::json!({
            "version": "2.0",
            "summary": {"text": "checkout threat model"},
            "dfd": {
                "nodes": [
                    {"id": "actor-user", "type": "external-entity", "name": "User"},
                    {"id": "web", "type": "process", "name": "Web"},
                    {"id": "db", "type": "data-store", "name": "DB"}
                ],
                "flows": [{"id": "flow-1", "sourceId": "actor-user", "targetId": "web"}],
                "trustBoundaries": [{"id": "tb-1", "name": "edge"}]
            },
            "threats": [{"id": "T-1", "category": "spoofing", "title": "stolen token"}],
            "assumptions": ["session cookies are in scope"],
            "missingInputs": ["production network diagram"]
        }),
        true,
    )
    .unwrap();
    // Tall enough for the whole summary document: the Threat view scrolls
    // beneath a pinned header now, and this test asserts full content.
    let backend = TestBackend::new(132, 48);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.router.threat_mut().open(ThreatView::Summary);
    app.set_shell_view(ShellView::Threat);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL REVIEW"));
    assert!(rendered.contains("checkout threat model"));
    assert!(rendered.contains("assets             3"));
    assert!(rendered.contains("actors             1"));
    assert!(rendered.contains("data flows         1"));
    assert!(rendered.contains("trust boundaries   1"));
    assert!(rendered.contains("session cookies are in scope"));
    assert!(rendered.contains("production network diagram"));
    assert!(rendered.contains("none pending"));
    assert!(rendered.contains("not exploit proof"));
    assert!(rendered.contains(".kuzushi/threat-model.json"));
    assert!(!rendered.contains("admin.acme-checkout.com"));
    assert!(!rendered.contains("shares the jwt secret"));
}

#[test]
fn threats_editor_names_persistent_artifact_path() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ThreatEditor);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL EDIT"));
    assert!(rendered.contains(".kuzushi/threat-model.json"));
}

#[test]
fn threats_summary_unknown_state_does_not_invent_data() {
    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Summary);
    app.set_shell_view(ShellView::Threat);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THREAT MODEL REVIEW"));
    assert!(rendered.contains("select a target before loading threat-model artifacts"));
    assert!(rendered.contains("assets"));
    assert!(rendered.contains("no target selected"));
    assert!(rendered.contains("targetless browsing does not inspect cwd"));
    assert!(!rendered.contains("admin.acme-checkout.com"));
}

#[test]
fn threats_stride_view_without_a_target_names_the_targetless_state() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.threat_mut().open(ThreatView::Stride);
    app.set_shell_view(ShellView::Threat);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("STRIDE ROLLUP"),
        "expected STRIDE ROLLUP header in: {rendered}"
    );
    assert!(rendered.contains("select a target before loading threat-model artifacts"));
    // No category row may claim a count the target never produced.
    assert!(!rendered.contains("Spoofing"), "{rendered}");
    assert!(!rendered.contains("Info-disclosure"), "{rendered}");
    assert!(!rendered.contains("aud-claim"), "{rendered}");
}

#[test]
fn recon_module_is_focusable_from_catalog() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();

    assert!(app
        .registry()
        .modules()
        .any(|module| module.metadata().id == "recon"));
    assert!(app.registry().resolve_tool("recon:nmap").is_some());
}

#[test]
fn focused_offense_review_module_renders_recent_threat_hunt_activity() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.clear_log();
    app.log("offense-review", "actor 1/4 dispatched");
    app.log("offense-review", "actor 2/4 found path-traversal sink");
    run_command(
        &mut app,
        crate::commands::ShellCommand::Use("offense-review".to_string()),
    );

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TOOLS · module:offense-review"));
    assert!(rendered.contains("offense-review:threat-hunt"));
    assert!(rendered.contains("SCAN"));
    assert!(!rendered.contains("RECENT THREAT-HUNT ACTIVITY"));
}

#[test]
fn module_run_transcript_uses_growing_console_glyphs() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.clear_log();
    app.log(">", "/scan");
    app.log("scan", "starting ./demo");
    app.log("finding", "abc123 high dangerous sink");
    app.log("error", "scanner failed");
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-123456".to_string()),
        target: std::path::PathBuf::from("./demo"),
        stage: "agentic-sast tracing".to_string(),
        findings_count: 1,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::ModuleRun);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SCAN PROGRESS"));
    // Spinner cycles through SPINNER_FRAMES based on `app.ui().spinner_phase()`; any frame is valid.
    assert!(
        SPINNER_FRAMES.iter().any(|frame| rendered.contains(frame)),
        "expected one of the braille spinner frames in: {rendered}"
    );
    assert!(rendered.contains("● /scan"));
    assert!(rendered.contains("⏵ scan starting ./demo"));
    assert!(rendered.contains("▸ finding abc123 high dangerous sink"));
    assert!(rendered.contains("✗ error scanner failed"));
}

#[test]
fn direct_tool_run_header_does_not_show_pending_scan_run() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("context".to_string()));
    app.set_shell_view(ShellView::ModuleRun);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("tool run"));
    assert!(rendered.contains("CONTEXT BUILD"));
    assert!(rendered.contains(".kuzushi/context-snapshot.json"));
    assert!(!rendered.contains("SCAN PROGRESS"));
    assert!(!rendered.contains("run pending"));
}

#[test]
fn active_tool_run_uses_live_tool_chrome_not_scan_chrome() {
    let backend = TestBackend::new(96, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("recon".to_string()));
    app.set_running_tool_for_test("recon:nmap");
    app.set_shell_view(ShellView::ModuleRun);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TOOL RUN"));
    assert!(rendered.contains("recon:nmap"));
    assert!(
        SPINNER_FRAMES.iter().any(|frame| rendered.contains(frame)),
        "expected active spinner frame in: {rendered}"
    );
    assert!(!rendered.contains("SCAN PROGRESS"));
    assert!(!rendered.contains("no scan in flight"));
}

#[test]
fn renders_options_table_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.router.set_options(crate::app::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::app::OptionsFilter::Standard,
    });
    app.set_shell_view(ShellView::Options);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("sast:scan"));
    assert!(rendered.contains("tasks"));
    assert!(rendered.contains("disabledTasks"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("yes"));
    assert!(rendered.contains("set <key> <value>"));
    assert!(rendered.contains("lost on exit"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn narrow_options_viewport_uses_every_advertised_scroll_key() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.open_options_for_test(crate::app::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::app::OptionsFilter::Standard,
    });
    app.set_input_mode(crate::InputMode::Navigate);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
    );
    assert_eq!(app.router.default_scroll().offset(), 1);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
    );
    assert_eq!(app.router.default_scroll().offset(), 0);

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT),
    );
    assert_eq!(app.router.default_scroll().offset(), u16::MAX);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let bottom = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(
        bottom.contains("triage"),
        "bottom options missing: {bottom}"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
    );
    assert_eq!(app.router.default_scroll().offset(), 0);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    assert!(app.router.default_scroll().offset() > 1);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let paged = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(paged.contains("triage"), "paged options missing: {paged}");
    press_key(&mut app, KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
    assert_eq!(app.router.default_scroll().offset(), 0);
}

#[test]
fn narrow_sast_tasks_and_config_use_the_default_viewport() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(crate::TerminalViewport::new(60, 20));
    let last_task = crate::ui_view_models::sast_tasks_model(&app)
        .rows
        .last()
        .expect("SAST task fixture")
        .task_id;
    app.set_shell_view(ShellView::SastTasks);
    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
    );
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let tasks = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(tasks.contains(last_task), "last SAST task missing: {tasks}");

    app.set_shell_view(ShellView::Config);
    app.sync_view_change();
    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT),
    );
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let config = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(
        config.contains("Enter model picker"),
        "Config's final action must remain reachable after the model list grows: {config}"
    );

    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
    );
    press_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(
        app.router.default_scroll().offset(),
        1,
        "Config arrows scroll the document"
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
    );
    assert_eq!(app.router.default_scroll().offset(), 2);
}

#[test]
fn renders_sast_task_picker_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::SastTasks);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("SAST TASKS"));
    assert!(rendered.contains("semgrep"));
    assert!(rendered.contains("codeql"));
    assert!(rendered.contains("auto + denylist"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn plain_sast_tasks_explains_task_state_markers() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::SastTasks);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("[A] advanced"), "{rendered}");
    assert!(rendered.contains("[B] blocked"), "{rendered}");
}

#[test]
fn renders_kb_attachments_readably_at_80_columns() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().kb_view_mut().module_id = "x-ray".to_string();
    app.domain_mut().kb_view_mut().artifacts = vec![kuzushi_core::KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "x-ray/x-ray.md".to_string(),
        description: "x-ray report".to_string(),
        exists: true,
    }];
    app.domain_mut().kb_view_mut().attachments = vec![kuzushi_core::AttachmentRecord {
        id: "A-123456789abc".to_string(),
        module_id: "x-ray".to_string(),
        kind: kuzushi_core::AttachmentKind::Url,
        source: "https://example.test/design".to_string(),
        title: "example.test".to_string(),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "metadata-only; URL was not fetched".to_string(),
        updated_at_unix: 1,
    }];
    app.set_shell_view(ShellView::KnowledgeBase);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("KB ATTACHMENTS"));
    assert!(rendered.contains("x-ray/x-ray.md"));
    assert!(rendered.contains("A-123456789abc"));
    assert!(rendered.contains("metadata-only"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_context_status_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_context_view(crate::app::ContextSnapshotView {
            snapshot_path: Some(context_snapshot_fixture_path()),
            exists: true,
            freshness: Some(kuzushi_core::context::ContextSnapshotFreshness::Current),
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
            enrichment_claims: 0,
            enrichment_model: None,
        });
    app.set_shell_view(ShellView::Context);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CONTEXT"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(rendered.contains("Rust"));
    assert!(rendered.contains("context regen repo"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn active_context_build_view_shows_live_feedback() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("context".to_string()));
    app.set_shell_view(ShellView::Context);
    app.set_running_tool_for_test("context:build");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("run route"));
    assert!(rendered.contains("context:build"));
    assert!(rendered.contains("indexing repository context"));
    assert!(rendered.contains("request abort"));
    assert!(rendered.contains("kuzushi/context/run>"));
    assert!(!rendered.contains("SCAN PROGRESS"));
}

#[test]
fn context_build_view_surfaces_malformed_snapshot() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("context".to_string()));
    app.set_shell_view(ShellView::Context);
    app.domain_mut().context_view_mut().snapshot_path = Some(context_snapshot_fixture_path());
    app.domain_mut().context_view_mut().status =
        "malformed context snapshot. Next: context build".to_string();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("malformed context snapshot"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(!rendered.contains("no snapshot yet"));
}

#[test]
fn renders_workspace_status_readably_at_80_columns() {
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().set_workspace_view(crate::app::WorkspaceView {
        root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v3")),
        findings_db: Some(std::path::PathBuf::from(
            "/tmp/kuzushi-demo/.kuzushi/v3/index.sqlite3",
        )),
        findings_count: Some(2),
        last_export: Some(std::path::PathBuf::from("/tmp/findings.json")),
        status: "workspace ready; 2 finding(s). Next: workspace scope init or workspace export findings <path> [format] [--completeness open|complete] [--allow-empty]"
            .to_string(),
    });
    app.set_shell_view(ShellView::Workspace);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("WORKSPACE"));
    assert!(rendered.contains("index.sqlite3"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("workspace export"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn workspace_view_renders_findings_rollup_bar_when_findings_exist() {
    // Mockup parity: `design/mockups/workspace.jsx::rollupBar`. With
    // persisted findings, the workspace view shows a 28-cell severity
    // rollup bar per category so the operator sees the distribution
    // shape at a glance.
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_workspace_view(crate::app::WorkspaceView {
            root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
            state_dir: None,
            findings_db: None,
            findings_count: Some(38),
            last_export: None,
            status: "workspace ready".to_string(),
        });
    *app.findings_mut() = (0..38)
        .map(|index| {
            let sev = match index % 4 {
                0 => Severity::Critical,
                1 => Severity::High,
                2 => Severity::Medium,
                _ => Severity::Low,
            };
            Finding::new_semgrep(
                format!("rule.{index}"),
                "src/x.rs",
                index + 1,
                None,
                sev,
                "demo",
            )
        })
        .collect();
    app.set_shell_view(ShellView::Workspace);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains("FINDINGS ROLLUP"),
        "missing rollup divider: {rendered}"
    );
    assert!(rendered.contains("CRITICAL"));
    assert!(rendered.contains("HIGH"));
    assert!(rendered.contains("MEDIUM"));
    assert!(rendered.contains("LOW"));
    assert!(rendered.contains("█"));
    assert!(rendered.contains("░"));
    assert!(rendered.contains("/38"));
}

#[test]
fn workspace_view_skips_rollup_when_no_findings() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workspace);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // No findings → no FINDINGS ROLLUP section (no empty bars to show).
    assert!(!rendered.contains("FINDINGS ROLLUP"));
}

#[test]
fn plain_options_table_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store_mut().set_value(
        OptionScope::Session,
        OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.router.set_options(crate::app::OptionsView {
        tool_name: "sast:scan".to_string(),
        filter: crate::app::OptionsFilter::Standard,
    });
    app.set_shell_view(ShellView::Options);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("sast:scan"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("yes"));
    assert!(rendered.contains("lost on exit"));
    assert!(rendered.contains("Next: set <key> <value>"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_kb_list_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().kb_view_mut().module_id = "x-ray".to_string();
    app.domain_mut().kb_view_mut().artifacts = vec![kuzushi_core::KnownArtifact {
        module_id: "x-ray".to_string(),
        path: "x-ray/x-ray.md".to_string(),
        description: "x-ray report".to_string(),
        exists: true,
    }];
    app.domain_mut().kb_view_mut().attachments = vec![kuzushi_core::AttachmentRecord {
        id: "A-123456789abc".to_string(),
        module_id: "x-ray".to_string(),
        kind: kuzushi_core::AttachmentKind::Url,
        source: "https://example.test/design".to_string(),
        title: "example.test".to_string(),
        metadata_only: true,
        content_hash: None,
        byte_count: None,
        status: "metadata-only; URL was not fetched".to_string(),
        updated_at_unix: 1,
    }];
    app.set_shell_view(ShellView::KnowledgeBase);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("KB ATTACHMENTS"));
    assert!(rendered.contains("x-ray/x-ray.md"));
    assert!(rendered.contains("A-123456789abc"));
    assert!(rendered.contains("metadata-only"));
    assert!(rendered.contains("Next: kb [module]"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_context_status_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut()
        .set_context_view(crate::app::ContextSnapshotView {
            snapshot_path: Some(context_snapshot_fixture_path()),
            exists: true,
            freshness: Some(kuzushi_core::context::ContextSnapshotFreshness::Current),
            status: "snapshot present; 2 indexed file(s). Next: context regen repo".to_string(),
            target: Some("/tmp/demo".to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(2),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string(), "app-model".to_string()],
            stale_slices: Vec::new(),
            enrichment_claims: 0,
            enrichment_model: None,
        });
    app.set_shell_view(ShellView::Context);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("CONTEXT"));
    assert!(rendered.contains("context-snapshot.json"));
    assert!(rendered.contains("Rust"));
    assert!(rendered.contains("context regen repo"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn plain_context_guidance_wraps_without_truncating_next_steps() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Context);

    let rendered = render_plain_app(&app, 56);

    assert!(rendered.contains("No context snapshot exists yet."));
    assert!(rendered.contains(".kuzushi/context-snapshot.json"));
    assert!(rendered.contains("context build"));
    assert!(rendered.contains("context regen repo"));
    assert!(!rendered.contains("context-s..."));
    assert_strict_plain_width(&rendered, 56);
}

#[test]
fn plain_workspace_guidance_wraps_without_truncating_export_command() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.domain_mut().set_workspace_view(crate::app::WorkspaceView {
        root: Some(std::path::PathBuf::from("/tmp/kuzushi-demo")),
        state_dir: Some(std::path::PathBuf::from("/tmp/kuzushi-demo/.kuzushi/v3")),
        findings_db: Some(std::path::PathBuf::from(
            "/tmp/kuzushi-demo/.kuzushi/v3/index.sqlite3",
        )),
        findings_count: Some(2),
        last_export: None,
        status: "workspace ready; 2 finding(s). Next: workspace scope init or workspace export findings <path> [format] [--completeness open|complete] [--allow-empty]"
            .to_string(),
    });
    app.set_shell_view(ShellView::Workspace);

    let rendered = render_plain_app(&app, 52);

    assert!(rendered.contains("workspace ready; 2 finding(s)."));
    assert!(rendered.contains("workspace scope init"));
    assert!(rendered.contains("workspace export findings <path>"));
    assert!(rendered.contains("[--allow-empty]"));
    assert!(!rendered.contains("workspace export findings..."));
    assert_strict_plain_width(&rendered, 52);
}

#[test]
fn plain_help_guidance_wraps_without_truncating_command_shapes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);

    let rendered = render_plain_app(&app, 64);

    assert!(rendered.contains("HELP"));
    assert!(rendered.contains("ask <question>"));
    assert!(rendered.contains("enter agent mode"));
    assert!(rendered.contains("workspace export findings <path>"));
    assert!(rendered.contains("/workspace export findings <path>"));
    assert!(!rendered.contains("workspace export findings <..."));
    assert_strict_plain_width(&rendered, 64);
}

#[test]
fn renders_config_onboarding_without_silent_model_selection() {
    // Config now includes the complete effective-source inventory before the
    // expanded model catalog. Give this content test enough height to assert
    // both sections; compact viewport behavior is covered separately.
    let backend = TestBackend::new(100, 50);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config_mut().model = None;
    app.set_session_thinking_level(None);
    app.set_shell_view(ShellView::Config);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("provider"));
    assert!(rendered.contains("unconfigured"));
    assert!(rendered.contains("reasoning"));
    assert!(rendered.contains("default"));
    assert!(rendered.contains("onboarding"));
    assert!(rendered.contains("Up/Down"));
    assert!(rendered.contains(">"));
    assert!(rendered.contains("openai:gpt-5.5"));
    assert!(rendered.contains("openai-oauth:gpt-5.6-terra"));
    assert!(rendered.contains("anthropic:claude-sonnet-4-6"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn plain_config_onboarding_uses_explicit_model_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.config_mut().model = None;
    app.set_session_thinking_level(None);
    app.set_shell_view(ShellView::Config);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("CONFIG"));
    assert!(rendered.contains("model: unconfigured"));
    assert!(rendered.contains("onboarding: model <n> selects an explicit provider:model"));
    assert!(rendered.contains("openai:gpt-5.5"));
    assert!(rendered.contains("openai-oauth:gpt-5.6-terra"));
    assert!(rendered.contains("anthropic:claude-sonnet-4-6"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn config_picker_renders_the_visible_candidate_and_returns_at_constrained_sizes() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    for (width, height) in [(40, 12), (80, 24), (120, 36)] {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".into());
        let mut app = ShellApp::new(config, None);
        app.set_shell_view(ShellView::Config);
        app.set_input_mode(crate::InputMode::Navigate);
        app.sync_view_change();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let before = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(
            before.contains("Enter choose model") || before.contains("Enter model picker"),
            "{width}x{height}: {before}"
        );

        let opening = app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.sync_view_change();
        assert!(opening.effects.is_empty());
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let picker = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(picker.contains("CHOOSE A MODEL"), "{picker}");
        assert!(!picker.contains("NAVIGATION MODE"), "{picker}");
        assert!(picker.contains("▸ GPT-5.5"), "{picker}");
        assert!(picker.contains("Current: openai:gpt-5.5"), "{picker}");
        app.reduce_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let moved = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(moved.contains("▸ GPT-5.4 mini"), "{moved}");
        app.reduce_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let command = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(
            command.contains("Enter command") || command.contains("Enter run command"),
            "{command}"
        );
        assert!(!command.contains("Enter select"), "{command}");
        assert!(!command.contains("Enter: API key"), "{command}");
        app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(
            app.router.setup().editor(),
            Some(crate::app::SetupEditor::Model)
        );
        app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.sync_view_change();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let restored = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(restored.contains("CONFIG"), "{restored}");
        assert!(!restored.contains("CHOOSE A MODEL"), "{restored}");
        assert_eq!(app.config().model.as_deref(), Some("openai:gpt-5.5"));
    }
}

#[test]
fn permissions_surface_reports_dispatch_policy_in_tty_and_plain_modes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Permissions);

    let backend = TestBackend::new(100, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let tty = format!("{:?}", terminal.backend().buffer());

    assert!(tty.contains("permissions"));
    assert!(tty.contains("PERMISSION POLICY"));
    assert!(tty.contains("MODEL / RUNTIME"));
    assert!(tty.contains("SHELL RISK GATES"));
    assert!(!tty.contains("── CONFIG"));

    let plain = render_plain_app(&app, 72);
    assert!(plain.contains("PERMISSION POLICY"));
    assert!(plain.contains("explicit <module>:<tool>"));
    assert!(plain.contains("Recognized network egress"));
    assert!(plain.contains("destructive verbs are refused"));
    assert!(plain.contains("not an OS sandbox"));
    assert!(!plain.contains("onboarding: model"));
    assert_strict_plain_width(&plain, 72);
}

#[test]
fn renders_help_grouped_by_operator_workflow() {
    // The combined command catalog (jobs/queue/background/autonomy verbs plus
    // the SESSION group) is taller than the help view fit in previously;
    // render into a taller viewport so every group, including SESSION, is
    // actually painted instead of scrolled out of the test buffer.
    let backend = TestBackend::new(110, 240);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    for heading in [
        "NAVIGATION",
        "RUN / SCAN",
        "OPTIONS / TASKS",
        "CONTEXT / KB",
        "FINDINGS / EVIDENCE",
        "AUTH / CONFIG / MODEL",
        "SESSION",
    ] {
        assert!(rendered.contains(heading), "missing help group {heading}");
    }
    assert!(rendered.contains("options [tool]"));
    assert!(rendered.contains("task toggle"));
    assert!(rendered.contains("kb [module]"));
    assert!(rendered.contains("auth login"));
    assert!(rendered.contains("? opens help"));
    assert!(rendered.contains("?text"));
    assert!(rendered.contains("/ask <question>"));
    assert!(rendered.contains("ask <question>"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn renders_help_aliases_and_examples_from_command_specs() {
    // Keep the complete command catalog in the viewport. Adding a public
    // command must not turn this contract into a scroll-position test.
    let backend = TestBackend::new(120, 320);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    for example in shell_help_examples() {
        assert!(
            rendered.contains(example),
            "missing featured help example {example}"
        );
    }

    for (category, alias) in [
        (ShellCommandCategory::Navigation, "/h"),
        (ShellCommandCategory::RunScan, "run ."),
        (ShellCommandCategory::OptionsTasks, "task deny <id>"),
        (ShellCommandCategory::ContextKb, "attachments"),
        (ShellCommandCategory::FindingsEvidence, "open F-0001"),
        (ShellCommandCategory::AuthConfigModel, "model 1"),
        (ShellCommandCategory::Session, "q"),
    ] {
        assert!(
            shell_command_specs()
                .any(|spec| spec.category == category && spec.aliases.contains(&alias)),
            "sample alias {alias:?} is not registered for {category:?}"
        );
        assert!(
            rendered.contains(alias),
            "missing help alias sample {alias:?} for {category:?}"
        );
    }

    // Per `design/mockups/help.jsx`, sections embed their blurb on the
    // category divider rule line — no separate `aliases / examples` table
    // header.  The featured-example + per-category alias assertions
    // above already prove the alias/example text reaches the buffer.
    assert!(rendered.contains("browse modules and tools"));
    assert!(!rendered.contains("TypeScript"));
    assert!(!rendered.contains("Ink"));
}

#[test]
fn plain_help_aliases_and_examples_are_width_safe() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("HELP"));
    assert!(rendered.contains("browse modules and tools"));
    for example in [
        "kuzushi scan <target>",
        "kuzushi --target <target> run sast:scan",
        "findings export report.sarif sarif",
    ] {
        assert!(
            rendered.contains(example),
            "missing plain help example {example}"
        );
    }
    for alias in [
        "/h",
        "run .",
        "task deny <id>",
        "attachments",
        "open F-0001",
        "model 1",
        "q",
    ] {
        assert!(rendered.contains(alias), "missing plain help alias {alias}");
    }
    assert!(!rendered.contains("TypeScript"));
    assert!(!rendered.contains("Ink"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn viewport_help_remains_navigable_at_24_rows() {
    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);
    app.set_input_mode(crate::InputMode::Navigate);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let first_page = format!("{:?}", terminal.backend().buffer());
    assert!(first_page.contains("HELP"));
    assert!(first_page.contains("NAVIGATION"));

    *app.router.help_mut().scroll_mut() = usize::MAX;
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let last_page = format!("{:?}", terminal.backend().buffer());
    assert!(last_page.contains("KUZUSHI"), "{last_page}");
    assert!(last_page.contains("HELP"), "{last_page}");
    assert!(last_page.contains("rows "), "{last_page}");
    assert!(last_page.contains("quit"), "{last_page}");
    assert!(last_page.contains("PgUp/PgDn scroll"), "{last_page}");
    assert!(!last_page.contains("┌"));
}

#[test]
fn compact_logs_wrap_failure_cause_and_recovery_into_reachable_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.log(
        "error",
        "CodeQL database creation failed because no build command was detected. Next: choose Semgrep or configure a CodeQL build command, then retry.",
    );
    app.set_shell_view(ShellView::Logs);
    *app.router.logs_mut().scroll_mut() = usize::MAX;
    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    assert!(
        rendered.contains("build command was detected"),
        "{rendered}"
    );
    assert!(rendered.contains("Next:"), "{rendered}");
    assert!(rendered.contains("configure a CodeQL build"), "{rendered}");
    assert!(rendered.contains("then retry"), "{rendered}");
}

#[test]
fn viewport_tools_remain_navigable_at_24_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let last_tool = crate::ui_view_models::tools_model(&app)
        .groups
        .iter()
        .rev()
        .find_map(|group| group.rows.last())
        .unwrap()
        .cells[0]
        .clone();
    app.set_shell_view(ShellView::Tools);
    *app.router.tools_mut().scroll_mut() = usize::MAX;

    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains(&last_tool),
        "missing last tool {last_tool}"
    );
    assert!(rendered.contains("KUZUSHI"), "{rendered}");
    assert!(rendered.contains("TOOLS"), "{rendered}");
    assert!(rendered.contains("rows "), "{rendered}");
    assert!(rendered.contains("PgUp/PgDn scroll"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn viewport_expanded_modules_remain_navigable_at_24_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(crate::app::TerminalViewport::new(110, 24));
    app.set_shell_view(ShellView::Catalog);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router.catalog_mut().expand();
    let model = crate::ui_view_models::catalog_model(&app);
    let last_action = model
        .groups
        .iter()
        .rev()
        .find_map(|group| group.rows.last())
        .expect("expanded capabilities should expose expert actions")
        .cells[0]
        .clone();
    app.router.catalog_mut().jump_end(model.module_count);
    app.move_catalog_cursor(0);

    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(
        rendered.contains(&last_action),
        "missing last capability {last_action}"
    );
    assert!(rendered.contains("PgUp/PgDn scroll"));
    assert!(!rendered.contains("┌"));
}

#[test]
fn workbench_findings_pane_windows_cursor_into_view() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.router.findings_mut().set_cursor(29);
    *app.findings_mut() = (0..30)
        .map(|index| {
            let mut finding = Finding::new_semgrep(
                format!("demo.rule.{index:04}"),
                "src/app.rs",
                index + 1,
                None,
                Severity::High,
                format!("title-{index:02}\nEvidence: proof-{index:02}"),
            );
            finding.fingerprint = format!("fp-{index:04}");
            finding
        })
        .collect();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // The review queue windows around the cursor: the last alias is visible,
    // the first has scrolled off.
    assert!(rendered.contains("F-0030"));
    assert!(!rendered.contains("F-0001"));
}

#[test]
fn keybind_footer_advertises_workbench_navigation_keys_at_80_columns() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);
    *app.findings_mut() = vec![Finding::new_semgrep(
        "demo.rule",
        "src/app.rs",
        1,
        None,
        Severity::High,
        "title\nEvidence: proof",
    )];

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Enter open Prove"), "{rendered}");
    assert!(rendered.contains("j/k/↑/↓ move"), "{rendered}");
    assert!(rendered.contains("Shift+Tab phase→"), "{rendered}");
    assert!(rendered.contains("] pane"), "{rendered}");
    assert!(rendered.contains("Tab/[/] pane"), "{rendered}");
    assert!(rendered.contains("/keys all"), "{rendered}");
}

#[test]
fn keybind_footer_advertises_module_run_actor_and_pause_resume_keys() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let cancel = ScanCancellation::default();
    app.set_scan_cancel_for_test(cancel.clone());
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::ModuleRun);
    app.set_input_mode(crate::InputMode::Navigate);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let running = format!("{:?}", terminal.backend().buffer());
    assert!(running.contains("1..4 actor"));
    assert!(running.contains("p pause"));
    assert!(!running.contains("[actor 1]"));

    cancel.pause();
    if let Some(scan) = app.scan_mut() {
        scan.stage = "paused".to_string();
    }
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let paused = format!("{:?}", terminal.backend().buffer());
    assert!(paused.contains("1..4 actor"));
    assert!(paused.contains("r resume"));
    // The unbracketed pause hint is gone too (sanity: keybind list flips
    // pause→resume on pause).
    assert!(!paused.contains("p pause"));
}

#[test]
fn renders_honest_abort_requested_states() {
    let backend = TestBackend::new(96, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.set_shell_view(ShellView::ModuleRun);
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("run-1".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "abort requested".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: true,
        error: None,
    }));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let scan_rendered = format!("{:?}", terminal.backend().buffer());
    assert!(scan_rendered.contains("abort requested"));
    assert!(scan_rendered.contains("waiting for subprocess"));
    assert!(!scan_rendered.contains("killed"));
}

#[test]
fn failure_handoff_view_renders_current_context() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_agent_chat(Some(crate::app::AgentChatView {
        recovery_note: None,
        partial_answer: String::new(),
        question: String::new(),
        answer: None,
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        screen_context_scope: None,
        thread_context_key: None,
        attached_turn_count: 0,
        auxiliary_read_only: false,
        failure_context: Some(kuzushi_core::run_artifacts::FailureToLlmContext {
            failed_stage: "semgrep:scan".to_string(),
            cause: "semgrep binary missing".to_string(),
            what_failed: "semgrep:scan did not complete successfully".to_string(),
            artifacts_available: Vec::new(),
            missing_artifacts: vec!["findings.json".to_string()],
            allowed_proof_level: "artifact-review-only; runtime verification did not run"
                .to_string(),
            next_files_or_artifacts_to_inspect: vec!["failures.json".to_string()],
            recovery_options: vec!["Install semgrep.".to_string()],
            fallback_prompt: "Continue the failed Kuzushi run.".to_string(),
            claims_forbidden: vec!["verified".to_string()],
            resume_from: None,
            completed_stages: Vec::new(),
            checkpoint_artifacts: Vec::new(),
            checkpoint_fingerprint: None,
            runtime_failure: None,
            model: None,
        }),
        pending_failure_context: None,
    }));
    app.set_shell_view(ShellView::FailureHandoff);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("FAILURE HANDOFF"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("Continue the failed Kuzushi run."));
}

#[test]
fn failure_handoff_view_reads_latest_failures_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    kuzushi_core::write_run_summary(
        tmp.path(),
        &RunSummary::running("run-1", "tool", None, tmp.path().display().to_string()),
    )
    .unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(
        run_dir.join("failures.json"),
        serde_json::json!({
            "runId": "run-1",
            "status": "failed",
            "failures": [{
                "tool": "semgrep:scan",
                "status": "failed",
                "error": "semgrep binary missing",
                "agentThreadContext": {
                    "failedStage": "semgrep:scan",
                    "cause": "semgrep binary missing",
                    "whatFailed": "semgrep:scan did not complete successfully",
                    "artifactsAvailable": [],
                    "missingArtifacts": ["findings.json"],
                    "allowedProofLevel": "artifact-review-only; runtime verification did not run",
                    "nextFilesOrArtifactsToInspect": ["failures.json"],
                    "recoveryOptions": ["Install semgrep."],
                    "fallbackPrompt": "Continue the failed Kuzushi run.",
                    "claimsForbidden": ["verified"]
                }
            }]
        })
        .to_string(),
    )
    .unwrap();

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_shell_view(ShellView::FailureHandoff);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("FAILURE HANDOFF"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("findings.json"));
    assert!(rendered.contains("Continue the failed Kuzushi run."));
}

#[test]
fn recommend_view_renders_latest_recommendations_artifact() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "run-1");
    std::fs::create_dir_all(&run_dir).unwrap();
    kuzushi_core::write_run_summary(
        tmp.path(),
        &RunSummary::running("run-1", "tool", None, tmp.path().display().to_string()),
    )
    .unwrap();
    std::fs::write(ui_latest_run_path(Some(tmp.path())), "run-1\n").unwrap();
    std::fs::write(
        run_dir.join("recommendations.json"),
        serde_json::json!([
            {
                "tool": "semgrep:scan",
                "priority": "high",
                "reason": "Source files match the fast native SAST path.",
                "signals": ["frameworks: Falcon, Litestar, Sanic"],
                "requiresRuntime": false
            }
        ])
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        run_dir.join("attack-surface.json"),
        serde_json::json!({
            "summary": {
                "highRisk": 1,
                "maxRiskScore": 90,
                "byRiskTier": {"critical": 1}
            },
            "surfaces": [{
                "framework": "Spring",
                "title": "POST /admin",
                "risk": {"tier": "critical"}
            }, {
                "framework": "Next.js",
                "title": "POST /api/session",
                "risk": {"tier": "medium"}
            }]
        })
        .to_string(),
    )
    .unwrap();

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_shell_view(ShellView::Recommend);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RECOMMEND"));
    assert!(rendered.contains("semgrep:scan"));
    assert!(rendered.contains("surface risk"));
    assert!(rendered.contains("1 high/critical"));
    assert!(rendered.contains("critical=1"));
    assert!(rendered.contains("frameworks Next.js=1, Spring=1"));
    assert!(rendered.contains("frameworks: Falcon"));
    assert!(rendered.contains("⚠ high"));
    assert!(rendered.contains("Source files match"));
}

#[test]
fn renders_shell_module_plan_and_run_routing_modes() {
    let cases = [
        {
            let app = ShellApp::new(V2Config::default(), None);
            (app, "shell route", "kuzushi>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_focused_module(Some("sast".to_string()));
            app.set_shell_view(ShellView::Module);
            (app, "module route", "kuzushi/sast>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_pending_plan(crate::app::PlanProposal {
                goal: "tighten SAST options".to_string(),
                summary: "set scanner controls".to_string(),
                changes: Vec::new(),
                unsupported: Vec::new(),
            });
            (app, "plan route", "kuzushi/plan>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_scan_panel(Some(crate::app::ScanPanelState {
                run_id: Some("run-1".to_string()),
                target: std::path::PathBuf::from("."),
                stage: "running semgrep".to_string(),
                findings_count: 0,
                running: true,
                abort_requested: false,
                error: None,
            }));
            app.set_shell_view(ShellView::ModuleRun);
            (app, "run route", "kuzushi/run>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_focused_module(Some("context".to_string()));
            app.set_shell_view(ShellView::ModuleRun);
            (app, "module route", "kuzushi/context>")
        },
        {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_focused_module(Some("context".to_string()));
            app.set_running_tool_for_test("context:build");
            app.set_shell_view(ShellView::ModuleRun);
            (app, "run route", "kuzushi/context/run>")
        },
    ];

    for (app, mode, prompt) in cases {
        let backend = TestBackend::new(96, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains(mode), "missing {mode} in {rendered}");
        assert!(rendered.contains("KUZUSHI"), "missing brand in {rendered}");
        assert!(
            rendered.contains(" route"),
            "missing mode chip in {rendered}"
        );
        assert!(
            rendered.contains("target:"),
            "missing target chip in {rendered}"
        );
        assert!(
            rendered.contains("context"),
            "missing context chip in {rendered}"
        );
        assert!(
            rendered.contains("model:"),
            "missing model chip in {rendered}"
        );
        assert!(
            !rendered.contains("KUZUSHI  mode "),
            "old cockpit strip remained in {rendered}"
        );
        assert!(rendered.contains(prompt), "missing {prompt} in {rendered}");
        assert!(!rendered.contains("┌"));
    }
}

#[test]
fn renders_all_ink_parity_shell_surfaces() {
    let cases = vec![
        (ShellView::Home, "HOME", None, None),
        (ShellView::Catalog, "CAPABILITIES", None, None),
        (ShellView::Recommend, "RECOMMEND", None, None),
        (ShellView::Module, "MODULE DETAIL", None, None),
        (ShellView::ModuleRun, "TRANSCRIPT", None, None),
        (ShellView::Workbench, "FINDING", None, None),
        (ShellView::Tune, "TUNE", None, None),
        (
            ShellView::Threat,
            "STORIES",
            Some(ThreatView::Stories),
            None,
        ),
        (ShellView::ThreatEditor, "THREAT MODEL EDIT", None, None),
        (ShellView::PromptsEditor, "PROMPTS", None, None),
        (ShellView::ActorDetail, "ACTOR 0", None, None),
        (ShellView::Runs, "RUN TIMELINE", None, None),
        (ShellView::RunDiff, "RUN DIFF", None, None),
        (ShellView::Replay, "REPLAY", None, None),
        (ShellView::Trace, "TRACE", None, None),
        (ShellView::Help, "HELP", None, None),
        (ShellView::Config, "CONFIG", None, None),
        (ShellView::Permissions, "PERMISSION POLICY", None, None),
        (ShellView::Health, "CURRENT PREFLIGHT", None, None),
        (ShellView::Tools, "TOOLS", None, None),
        (ShellView::Options, "OPTIONS", None, None),
        (ShellView::SastTasks, "SAST TASKS", None, None),
        (ShellView::Context, "CONTEXT", None, None),
        (ShellView::ProjectModel, "PROJECT MODEL", None, None),
        (ShellView::StrategyQueue, "STRATEGY QUEUE", None, None),
        (ShellView::Workspace, "WORKSPACE", None, None),
        (ShellView::KnowledgeBase, "KB ATTACHMENTS", None, None),
        (ShellView::FilePicker, "ATTACH A FILE", None, None),
        (ShellView::FailureHandoff, "FAILURE HANDOFF", None, None),
        (ShellView::History, "COMMAND HISTORY", None, None),
        (ShellView::Story, "SESSION STORY", None, None),
        (ShellView::Auth, "PROVIDERS", None, None),
        (ShellView::Cost, "BUDGETS", None, None),
        (ShellView::Patch, "PATCH", None, Some("F-0001")),
        (ShellView::Pwn, "PWN TARGET", None, None),
    ];

    for (view, expected, threat_view, patch_alias) in cases {
        let backend = TestBackend::new(110, 26);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_focused_module(Some("semgrep".to_string()));
        app.router.run_diff_mut().open("run-left", "run-right");
        app.router.replay_mut().open("run-1");
        app.router.trace_mut().open("run-1");
        if let Some(threat_view) = threat_view {
            app.router.threat_mut().open(threat_view);
        }
        if let Some(patch_alias) = patch_alias {
            app.router.patch_mut().open(patch_alias);
        }
        // The phase Workbench is the one box-drawing primary surface
        // (bordered panes); every other view stays line-based.
        let is_workbench = matches!(view, ShellView::Workbench);
        app.set_shell_view(view);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains(expected),
            "missing {expected} in {rendered}"
        );
        if !is_workbench {
            assert!(!rendered.contains("┌"), "{expected} drew a box");
        }
    }
}

#[test]
fn renders_pwn_dashboard_with_state_and_rounds() {
    let backend = TestBackend::new(110, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Pwn);
    let pwn = app.pwn_view_mut();
    pwn.target = Some(std::path::PathBuf::from("./chal"));
    pwn.profile_snapshot = Some(serde_json::json!({
        "arch": "x86-64",
        "needed": ["libc.so.6"]
    }));
    pwn.state_snapshot = Some(serde_json::json!({
        "primitives": [{
            "kind": "leak",
            "confidence": 0.75,
            "evidence": "controlled pointer disclosure",
            "remoteSafe": true
        }]
    }));
    pwn.auto_solve_snapshot = Some(serde_json::json!({
        "llmPlanner": {
            "iterations": [{
                "round": 0,
                "decision": {
                    "actions": [{"operation": "reverse-function", "function": "main"}]
                }
            }]
        }
    }));
    pwn.reverse_snapshots.push(serde_json::json!({
        "function": "main",
        "revng": {"ok": true, "output": "void main() { puts(\"hi\"); }"},
        "dangerousIo": ["puts"]
    }));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("PWN TARGET"));
    assert!(rendered.contains("leak"));
    assert!(rendered.contains("round 0"));
    assert!(rendered.contains("revng ok"));
}

fn buffer_row_text(buffer: &Buffer, width: u16, y: u16) -> String {
    let mut text = String::new();
    for x in 0..width {
        text.push_str(buffer[(x, y)].symbol());
    }
    text
}

fn assert_strict_plain_80(rendered: &str) {
    assert_strict_plain_width(rendered, 80);
}

fn assert_strict_plain_width(rendered: &str, width: usize) {
    assert!(
        !rendered.contains('\u{1b}'),
        "plain output contained ANSI escape: {rendered:?}"
    );
    assert!(
        !rendered
            .chars()
            .any(|ch| ('\u{2500}'..='\u{257f}').contains(&ch)),
        "plain output contained box drawing: {rendered:?}"
    );
    for line in rendered.lines() {
        assert!(
            line.chars().count() <= width,
            "plain line exceeded {width} columns: {line:?}"
        );
    }
}

#[test]
fn header_hides_cost_at_zero_and_compacts_at_higher_amounts() {
    // The design chrome reserves a cost chip on every screen. Keep exact zero
    // tidy while preserving four decimals for tiny nonzero model spend, then
    // compact larger values.
    assert_eq!(format_session_cost(0.0), "$0.00");
    assert_eq!(format_session_cost(0.0042), "$0.0042");
    assert_eq!(format_session_cost(0.42), "$0.42");
    assert_eq!(format_session_cost(12.345), "$12.35");
    assert_eq!(format_session_cost(245.6), "$246");

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(0.0);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(
        rendered.contains("cost:$0.00"),
        "header should render zero-cost chip: {rendered}"
    );

    // Once a real cost is reported we expect the compact spend value.
    app.session_mut().set_session_cost_usd_for_test(0.42);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("cost:$0.42"));
}

#[test]
fn module_run_error_wraps_on_word_boundaries() {
    // P4-4: previously the SCAN PROGRESS panel rendered the scan error
    // as a single line that was truncated mid-word, hiding the
    // actionable install command. Verify the renderer now uses
    // wrap_text so the next-step suggestion survives the wrap.
    use std::path::PathBuf;
    let backend = TestBackend::new(72, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModuleRun);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("abc1234".to_string()),
        target: PathBuf::from("./repo"),
        stage: "failed".to_string(),
        findings_count: 0,
        running: false,
        abort_requested: false,
        error: Some(
            "semgrep: could not find scanner binary \"semgrep\". Install Semgrep \
                 (for example `pipx install semgrep` or `brew install semgrep`)."
                .to_string(),
        ),
    }));
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("pipx install semgrep"));
    assert!(rendered.contains("brew install semgrep"));
}

#[test]
fn prompt_segments_highlight_follows_app_cursor() {
    // Cursor at the END of the input — the cursor cell is the trailing
    // glyph, before_cursor contains the whole input.
    let segments = prompt_segments("kuzushi> ", "abcdef", 6, 40, " ");
    assert_eq!(segments.before_cursor, "abcdef");
    assert_eq!(segments.cursor_text, " ");
    assert_eq!(segments.after_cursor, "");

    // Cursor in the middle — the cursor cell is the char it sits on.
    let segments = prompt_segments("kuzushi> ", "abcdef", 4, 40, " ");
    assert_eq!(segments.before_cursor, "abcd");
    assert_eq!(segments.cursor_text, "e");
    assert_eq!(segments.after_cursor, "f");

    // Cursor at the start — first char becomes the cursor cell.
    let segments = prompt_segments("kuzushi> ", "abcdef", 0, 40, " ");
    assert_eq!(segments.before_cursor, "");
    assert_eq!(segments.cursor_text, "a");
    assert_eq!(segments.after_cursor, "bcdef");

    // Cursor past the end is clamped to len so we don't panic on stale
    // indices coming from history-restore races.
    let segments = prompt_segments("kuzushi> ", "abc", 99, 40, " ");
    assert_eq!(segments.before_cursor, "abc");
    assert_eq!(segments.cursor_text, " ");
}

#[test]
fn view_status_segment_reflects_actual_view_not_focused_module() {
    // P1-2: previously the bottom status footer always read "catalog"
    // while the user was on Help / Tools / Findings. Verify the helper
    // returns the real view label so the status reflects what the user
    // actually sees.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Help);
    assert_eq!(view_status_segment(&app), "help");

    app.set_shell_view(ShellView::Catalog);
    assert_eq!(view_status_segment(&app), "capabilities");

    app.set_shell_view(ShellView::Tools);
    assert_eq!(view_status_segment(&app), "tools");

    app.set_shell_view(ShellView::Workbench);
    assert_eq!(view_status_segment(&app), "workbench");

    app.router.threat_mut().open(ThreatView::Stride);
    app.set_shell_view(ShellView::Threat);
    assert_eq!(view_status_segment(&app), "threats:stride");

    app.set_shell_view(ShellView::Runs);
    assert_eq!(view_status_segment(&app), "run-timeline");

    app.set_shell_view(ShellView::FailureHandoff);
    assert_eq!(view_status_segment(&app), "failure-handoff");

    // Module view still surfaces the focused module so operators can
    // see which module they're driving.
    app.set_focused_module(Some("semgrep".to_string()));
    app.set_shell_view(ShellView::Module);
    assert_eq!(view_status_segment(&app), "semgrep");
}

fn line_text(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

#[test]
fn progress_bar_line_matches_design_glyphs_and_count() {
    let line = progress_bar_line(
        "semgrep",
        612,
        612,
        "done · 18 raw hits",
        ProgressKind::Done,
    );
    let text = line_text(&line);
    assert!(text.contains("semgrep"));
    assert!(text.contains("[████████████████████████]"));
    assert!(text.contains("612/612"));
    assert!(text.contains("done · 18 raw hits"));
}

#[test]
fn progress_bar_line_partial_fills_proportionally() {
    let line = progress_bar_line("agentic-sast", 87, 120, "tracing…", ProgressKind::Active);
    let text = line_text(&line);
    // 87/120 = 0.725; round(0.725 * 24) = 17 filled, 7 empty
    let filled = text.matches('█').count();
    let empty = text.matches('░').count();
    assert_eq!(filled, 17, "expected 17 filled bars: {text:?}");
    assert_eq!(empty, 7, "expected 7 empty bars: {text:?}");
    assert!(text.contains("87/120"));
}

#[test]
fn progress_bar_line_zero_total_renders_empty() {
    let line = progress_bar_line("idle", 0, 0, "queued", ProgressKind::Queued);
    let text = line_text(&line);
    assert_eq!(text.matches('█').count(), 0);
    assert_eq!(text.matches('░').count(), 24);
}

#[test]
fn section_header_uppercases_and_pads_dashes() {
    // Per `design/mockups/_shared.jsx::sectionHeader`, the header lays
    // out as ` ── LABEL ──...─` (leading space, subtle rule, label,
    // subtle fill).  Uppercasing the label is preserved so e.g.
    // `findings · 11 triaged` still reads as `FINDINGS · 11 TRIAGED`.
    let line = section_header_line("findings · 11 triaged", 60);
    let text = line_text(&line);
    assert!(text.starts_with(" ── FINDINGS · 11 TRIAGED "));
    assert!(text.ends_with("─"));
    assert_eq!(text.chars().count(), 60);
}

#[test]
fn next_action_line_splits_run_tool_into_warn_primary_accent_muted() {
    // `design/mockups/catalog.jsx` paints the catalog NEXT line in four
    // colors: c-warn glyph, c-primary verb, c-accent tool name,
    // c-primary continuation, c-muted ambient suffix after ` — `.
    let line = next_action_line(
        "Run sast:scan against ~/work/acme-checkout — never run here, 0 findings on record",
        120,
    );

    // Verify the textual ordering by colour bucket — collect span
    // contents grouped by foreground style so the test fails loudly
    // if a future refactor flattens them back into one primary span.
    let mut buckets: Vec<(String, String)> = Vec::new();
    for span in &line.spans {
        let role = if span.style == theme::warn() {
            "warn"
        } else if span.style == theme::accent() {
            "accent"
        } else if span.style == theme::muted() {
            "muted"
        } else if span.style == theme::primary() {
            "primary"
        } else {
            "other"
        };
        buckets.push((role.to_string(), span.content.to_string()));
    }

    // Glyph + tool name + ambient suffix all show up in the right roles.
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "warn" && text.contains("▸ NEXT")),
        "warn glyph missing: {buckets:?}"
    );
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "accent" && text == "sast:scan"),
        "accent tool name missing: {buckets:?}"
    );
    assert!(
        buckets
            .iter()
            .any(|(role, text)| role == "muted" && text.contains("never run here")),
        "muted suffix missing: {buckets:?}"
    );
}

#[test]
fn plan_card_keybind_row_drops_bracket_chrome() {
    // The plan-card keybind row used to advertise `[j/k] move
    // [space] toggle [y] apply active [n] discard`. The mockups and
    // the rest of the shell use unbracketed `<key> <hint>` pairs
    // (see `keybindings_line` + `design/mockups/plan.jsx`).  Verify
    // the new spans reach the buffer without `[ ]` chrome.
    use crate::app::{PlanChange, PlanProposal};
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "demo".to_string(),
        summary: "demo summary".to_string(),
        changes: vec![PlanChange::Note {
            text: "stub change".to_string(),
        }],
        unsupported: vec![],
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PLAN"));
    assert!(rendered.contains("j/k move"));
    assert!(rendered.contains("space toggle"));
    assert!(rendered.contains("y apply active"));
    assert!(rendered.contains("n discard"));
    assert!(!rendered.contains("[j/k]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[space]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[y]"), "stale bracket: {rendered}");
    assert!(!rendered.contains("[n]"), "stale bracket: {rendered}");
}

#[test]
fn prereq_plan_card_shows_cached_missing_writes_risk_cost_and_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let context_snapshot_path = target_context_snapshot_path(tmp.path());
    std::fs::create_dir(context_snapshot_path.parent().unwrap()).unwrap();
    std::fs::write(context_snapshot_path, "{}\n").unwrap();
    let backend = TestBackend::new(132, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("carlini-threat-hunt:run", tmp.path()),
        "carlini-threat-hunt:run".to_string(),
        serde_json::json!({}),
        None,
    );
    app.engagement.set_pending_prereq_prompt(chain.plan());
    app.set_shell_view(ShellView::ModuleRun);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PREREQUISITE PLAN"));
    assert!(rendered.contains("carlini-threat-hunt:run"));
    assert!(rendered.contains("cached"));
    assert!(rendered.contains("missing"));
    assert!(rendered.contains("context snapshot"));
    assert!(rendered.contains("threat model"));
    assert!(rendered.contains("writes"));
    assert!(rendered.contains(".kuzushi"));
    assert!(rendered.contains("model-backed analysis"));
    assert!(rendered.contains("token cost unknown"));
    assert!(rendered.contains("a approve"));
    assert!(rendered.contains("r reuse cached"));
    assert!(rendered.contains("g regenerate"));
    assert!(rendered.contains("n cancel"));
}

#[test]
fn prereq_plan_card_explains_invalid_artifacts_before_reuse() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target_context_snapshot_path(tmp.path())).unwrap();
    let backend = TestBackend::new(132, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("sast:scan", tmp.path()),
        "sast:scan".to_string(),
        serde_json::json!({}),
        None,
    );
    app.engagement.set_pending_prereq_prompt(chain.plan());
    app.set_shell_view(ShellView::ModuleRun);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("invalid"));
    assert!(rendered.contains("invalid artifact"));
    assert!(rendered.contains("approve"));
    assert!(rendered.contains("regenerate"));
}

#[test]
fn plain_prereq_plan_has_no_ansi_or_box_drawing() {
    let tmp = tempfile::tempdir().unwrap();
    let context_snapshot_path = target_context_snapshot_path(tmp.path());
    std::fs::create_dir(context_snapshot_path.parent().unwrap()).unwrap();
    std::fs::write(context_snapshot_path, "{}\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    let chain = PrereqChain::new(
        prereq_steps_for("carlini-threat-hunt:run", tmp.path()),
        "carlini-threat-hunt:run".to_string(),
        serde_json::json!({}),
        None,
    );
    app.engagement.set_pending_prereq_prompt(chain.plan());

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("PREREQUISITE PLAN"));
    assert!(rendered.contains("cached context snapshot"));
    assert!(rendered.contains("missing threat model"));
    assert!(rendered.contains("actions: approve | reuse cached | regenerate | cancel"));
    assert!(rendered.contains(".kuzushi"));
    assert_strict_plain_80(&rendered);
}

#[test]
fn module_run_renders_live_activity_in_body_and_status_strip() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ModuleRun);
    app.set_live_activity_state(Some(LiveActivity::new(
        LiveActivityPhase::CallingModel,
        "triage:run",
        "asking model to triage persisted findings",
    )));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("LIVE ACTIVITY"));
    assert!(rendered.contains("calling model"));
    assert!(rendered.contains("triage:run"));
    assert!(rendered.contains("activity"));
    assert!(!rendered.contains("tool: active"));
}

#[test]
fn plain_live_activity_has_no_ansi_or_box_drawing() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let detail = format!("writes {}", threat_model_relative_path());
    app.set_live_activity_state(Some(LiveActivity::new(
        LiveActivityPhase::WritingArtifact,
        "threat-model:build",
        detail,
    )));

    let rendered = render_plain_app(&app, 80);

    assert!(rendered.contains("LIVE ACTIVITY"));
    assert!(rendered.contains("phase: writing artifact"));
    assert!(rendered.contains("subject: threat-model:build"));
    assert!(rendered.contains(&format!("detail: writes {}", threat_model_relative_path())));
    assert_strict_plain_80(&rendered);
}

#[test]
fn command_list_line_accents_each_command_with_subtle_separators() {
    // `command_list_line` builds the inline next-action hint that
    // appears at the bottom of many views (workspace, agent-chat,
    // history, kb).  The mockup paints commands in c-accent and
    // the ` · ` separator in c-subtle.
    let line = command_list_line(&["scan", "findings", "back"], 120);
    let mut accent_chunks = 0usize;
    let mut subtle_chunks = 0usize;
    for span in &line.spans {
        if span.style == theme::accent() {
            accent_chunks += 1;
        } else if span.style == theme::subtle() {
            subtle_chunks += 1;
        }
    }
    assert_eq!(accent_chunks, 3, "expected 3 accent commands");
    assert_eq!(subtle_chunks, 2, "expected 2 subtle middot separators");
}

#[test]
fn command_list_line_truncates_with_ellipsis_when_width_runs_out() {
    // Narrow width should drop trailing commands behind a subtle `…`
    // rather than overflow the row.
    let line = command_list_line(&["aaaaaaaa", "bbbbbbbb", "cccccccc"], 12);
    let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
    assert!(text.contains("…"), "missing ellipsis: {text}");
}

#[test]
fn runs_view_tints_status_column_per_mockup() {
    // `design/mockups/runs.jsx::r` paints the status cell with a
    // status-aware colour (complete → c-success, paused → c-warn,
    // failed → c-danger).  The Ratatui runs view used to leave
    // that column in default style.  Verify `runs_lines` puts the
    // success tint on a non-erroring scan and keeps the run-id
    // accent.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("r-08e1aa".to_string()),
        target: std::path::PathBuf::from("/tmp/demo"),
        stage: "complete".to_string(),
        findings_count: 11,
        running: false,
        abort_requested: false,
        error: None,
    }));
    app.set_shell_view(ShellView::Runs);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN TIMELINE"));
    assert!(rendered.contains("r-08e1aa"));
    assert!(rendered.contains("11"));
    // Verify by inspecting the line spans directly so we know the
    // status text is wearing the success style and the run id keeps
    // its accent style.
    let area = ratatui::layout::Rect::new(0, 0, 120, 22);
    let lines = runs_lines(&app, area);
    let row = lines
        .iter()
        .find(|line| line_text(line).contains("r-08e1aa"))
        .expect("run row missing");
    let mut saw_run_accent = false;
    let mut saw_status_success = false;
    for span in &row.spans {
        if span.content.contains("r-08e1aa") && span.style == theme::accent() {
            saw_run_accent = true;
        }
        if span.style == theme::success() {
            saw_status_success = true;
        }
    }
    assert!(saw_run_accent, "run id should be accent: {row:?}");
    assert!(saw_status_success, "status should be success: {row:?}");
}

#[test]
fn transcript_finding_line_tints_severity_per_mockup() {
    // `design/mockups/findings.jsx::findingRow` puts the severity in a
    // severity-tinted span, the rule-id in c-accent, and the location
    // in c-muted.  Verify `transcript_finding_line` builds the same
    // four-color split (warn glyph, severity tint, accent rule-id,
    // muted location).
    let line = transcript_finding_line(
        SeverityTone::Critical,
        "CRITICAL",
        "demo.rule",
        "src/x.rs:142",
    );
    let mut roles: Vec<&str> = Vec::new();
    for span in &line.spans {
        roles.push(if span.style == theme::warn() {
            "warn"
        } else if span.style == theme::severity_tone(SeverityTone::Critical) {
            "sev-critical"
        } else if span.style == theme::accent() {
            "accent"
        } else if span.style == theme::muted() {
            "muted"
        } else {
            "other"
        });
    }
    assert!(roles.contains(&"warn"), "warn glyph missing: {roles:?}");
    assert!(
        roles.contains(&"sev-critical"),
        "critical severity tint missing: {roles:?}"
    );
    assert!(
        roles.contains(&"accent"),
        "accent rule-id missing: {roles:?}"
    );
    assert!(
        roles.contains(&"muted"),
        "muted location missing: {roles:?}"
    );
}

#[test]
fn runs_view_lists_past_runs_from_run_json() {
    // Mockup parity: `design/mockups/runs.jsx` shows past runs as a
    // table with status tinting. Verify the run view model renders one
    // styled row per canonical run metadata file.
    let tmp = tempfile::tempdir().unwrap();
    let first = RunSummary::running("r-2026-05-06T14-31", "scan", None, "~/work/acme-checkout")
        .with_findings(Some(18))
        .complete();
    let mut second =
        RunSummary::running("r-2026-05-06T15-18", "scan", None, "~/work/acme-checkout")
            .with_findings(Some(0));
    second.status = "failed".to_string();
    kuzushi_core::write_run_summary(tmp.path(), &first).unwrap();
    kuzushi_core::write_run_summary(tmp.path(), &second).unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_shell_view(ShellView::Runs);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN TIMELINE"));
    // Both past runs reach the buffer with disambiguating short labels.
    assert!(rendered.contains(&crate::app::compact_run_reference(&first.run_id)));
    assert!(rendered.contains(&crate::app::compact_run_reference(&second.run_id)));
    assert!(rendered.contains("completed"));
    assert!(rendered.contains("failed"));
    assert!(rendered.contains("18"));
    assert!(rendered.contains("replay <runId>"));
}

#[test]
fn run_diff_view_renders_new_and_not_seen_findings_and_revisions() {
    let tmp = tempfile::tempdir().unwrap();
    write_run_diff_fixture(
        tmp.path(),
        "run-left",
        "abcdef123456",
        serde_json::json!([
            {"identityId":"fi_shared","fingerprint":"same","title":"shared","severity":"high","filePath":"src/lib.rs","startLine":10,"tool":"semgrep"},
            {"identityId":"fi_changed","fingerprint":"changed","title":"changed item","severity":"medium","filePath":"src/change.rs","startLine":15,"tool":"semgrep","triage":{"confidence":"0.41","verdict":"needs_review"}},
            {"fingerprint":"line-old","ruleId":"demo.sql","title":"line shifted item","severity":"medium","filePath":"src/db.rs","startLine":20,"tool":"semgrep"},
            {"fingerprint":"not-seen","title":"not seen item","severity":"medium","filePath":"src/old.rs","startLine":20,"tool":"codeql"}
        ]),
    );
    write_run_diff_fixture(
        tmp.path(),
        "run-right",
        "123456789abc",
        serde_json::json!([
            {"identityId":"fi_shared","fingerprint":"same","title":"shared","severity":"high","filePath":"src/lib.rs","startLine":10,"tool":"semgrep"},
            {"identityId":"fi_changed","fingerprint":"changed","title":"changed item","severity":"high","filePath":"src/change.rs","startLine":15,"tool":"semgrep","triage":{"confidence":"0.91","verdict":"confirmed"}},
            {"fingerprint":"line-new","ruleId":"demo.sql","title":"line shifted item","severity":"high","filePath":"src/db.rs","startLine":24,"tool":"semgrep"},
            {"fingerprint":"new","title":"new item","severity":"critical","filePath":"src/new.rs","startLine":30,"tool":"cpg"}
        ]),
    );
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    *app.findings_mut() = vec![
        run_diff_reviewed_finding("fi_shared", TriageVerdict::TruePositive),
        run_diff_reviewed_finding("fi_changed", TriageVerdict::FalsePositive),
    ];
    app.router.run_diff_mut().open("run-left", "run-right");
    app.set_shell_view(ShellView::RunDiff);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RUN DIFF"));
    assert!(rendered.contains("rev:abcdef1"));
    assert!(rendered.contains("rev:1234567"));
    assert!(rendered.contains("NEW IN RIGHT"));
    assert!(rendered.contains("new item"));
    assert!(rendered.contains("decisions: identities=2"));
    assert!(rendered.contains("conflicts=1"));
    assert!(rendered.contains("CHANGED IN RIGHT"));
    assert!(rendered.contains("changed item"));
    assert!(rendered.contains("UNCERTAIN MATCHES"));
    assert!(rendered.contains("line shifted item"));
    assert!(rendered.contains("review before carrying decisions"));
    assert!(rendered.contains("NOT SEEN IN RIGHT"));
    assert!(rendered.contains("not seen item"));
}

fn run_diff_reviewed_finding(identity_id: &str, verdict: TriageVerdict) -> Finding {
    let mut finding = Finding::new_semgrep(
        "demo.review",
        "src/app.ts",
        12,
        Some(12),
        Severity::High,
        "reviewed finding",
    );
    finding.identity_id = Some(identity_id.to_string());
    finding.triage = Some(TriageOutcome {
        verdict,
        confidence: 0.95,
        rationale: "loaded workspace review".to_string(),
        ..Default::default()
    });
    finding
}

fn write_run_diff_fixture(
    root: &std::path::Path,
    run_id: &str,
    sha: &str,
    findings: serde_json::Value,
) {
    let run_dir = ui_run_dir(Some(root), run_id);
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("run.json"),
        serde_json::json!({
            "status": "completed",
            "targetGit": {"sha": sha, "branch": "main", "dirty": false},
            "target": root.display().to_string()
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(run_dir.join("findings.json"), findings.to_string()).unwrap();
}

#[test]
fn catalog_j_k_moves_action_cursor_and_highlights_row() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, crate::commands::ShellCommand::Modules);
    app.set_input_mode(crate::InputMode::Navigate);

    // Cursor starts at 0; `j` advances it.
    let before = app.router.catalog().cursor();
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.catalog().cursor(), before + 1);

    // `k` reverses; from row 1 back to 0.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.catalog().cursor(), before);

    // Render after a `j` press; selection remains visible without color.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("▸"), "cursor glyph missing: {rendered}");
}

#[test]
fn catalog_enter_loads_selected_action_without_executing() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    run_command(&mut app, crate::commands::ShellCommand::Modules);
    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    );
    let command = app.catalog_cursor_command().expect("cursor command");
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()),
    );
    assert_eq!(app.input(), command);
    assert_eq!(app.input_mode(), crate::InputMode::Prompt);
    assert!(app.running_tool_name().is_none());
}

#[test]
fn catalog_g_and_uppercase_g_jump_cursor_to_bounds() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = ShellApp::new(V2Config::default(), None);
    run_command(&mut app, crate::commands::ShellCommand::Modules);
    app.set_input_mode(crate::InputMode::Navigate);
    let total = app.catalog_module_count();
    assert!(total > 0);

    // G jumps to last row.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.catalog().cursor(), total - 1);

    // g jumps to first.
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()),
    );
    assert_eq!(app.router.catalog().cursor(), 0);
}

#[test]
fn top_status_strip_shows_stage_spinner_while_scan_runs() {
    // `design/mockups/sast-running.jsx::customStrip` adds a `stage ⠿
    // running` segment to the top strip while a worker ticks.  Verify
    // the segment appears for a running scan and disappears when idle.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);

    // Idle: no stage segment.
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let idle = format!("{:?}", terminal.backend().buffer());
    assert!(
        !idle.contains("stage "),
        "stage shouldn't show idle: {idle}"
    );

    // Running: stage segment with spinner glyph.
    app.set_scan_panel(Some(crate::app::ScanPanelState {
        run_id: Some("r-now".to_string()),
        target: std::path::PathBuf::from("."),
        stage: "running".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let running = format!("{:?}", terminal.backend().buffer());
    assert!(running.contains("stage:"), "stage missing: {running}");
    assert!(running.contains("running"));
    // Any of the SPINNER_FRAMES shows up.
    let saw_spinner = SPINNER_FRAMES.iter().any(|f| running.contains(f));
    assert!(saw_spinner, "spinner glyph missing: {running}");
}

#[test]
fn cost_view_renders_budget_bar_and_session_spend() {
    // `/cost` (`design/mockups/cost.jsx`) shows BUDGETS bars +
    // SPEND key/values.  Verify both sections render and the bar
    // graphics + percentage reach the buffer.
    let backend = TestBackend::new(120, 26);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(1.42);
    app.session_mut().set_session_budget_usd(Some(5.0));
    app.session_mut()
        .set_last_tool_cost_usd_for_test(Some(0.18));
    app.set_shell_view(ShellView::Cost);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("BUDGETS"));
    assert!(rendered.contains("SPEND"));
    assert!(rendered.contains("█"));
    assert!(rendered.contains("░"));
    assert!(rendered.contains("$1.42"));
    assert!(rendered.contains("$5.00"));
    // 1.42 / 5.00 = 28.4% → 28%, success-tinted (< 85%).
    assert!(rendered.contains("28%"));
}

#[test]
fn auth_view_renders_providers_model_and_spend_sections() {
    // `/auth` should land on a dedicated ShellView::Auth surface
    // matching `design/mockups/auth.jsx` — providers list + effective
    // model + session spend.
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(
        V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        },
        None,
    );
    app.session_mut().set_session_cost_usd_for_test(0.42);
    app.set_shell_view(ShellView::Auth);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROVIDERS"));
    assert!(rendered.contains("MODEL"));
    assert!(rendered.contains("SPEND"));
    assert!(rendered.contains("openai:gpt-4.1"));
    assert!(rendered.contains("$0.42"));
    assert!(rendered.contains("auth login openai"));
    assert!(rendered.contains("github-copilot"));
}

#[test]
fn auth_view_renders_latest_oauth_flow_state() {
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Auth);
    app.router.auth_mut().set_login(AuthLoginView {
        provider: "openai".to_string(),
        method: "headless".to_string(),
        status: "waiting".to_string(),
        detail: "OpenAI device code flow".to_string(),
        store_path: "~/.kuzushi/oauth-credentials.json".to_string(),
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OAUTH"));
    assert!(rendered.contains("headless"));
    assert!(rendered.contains("OpenAI device code flow"));
    assert!(!rendered.contains("codex"));
    assert!(rendered.contains("oauth-credentials.json"));
}

#[test]
fn auth_view_stacks_and_wraps_on_narrow_terminals() {
    // Narrow panes (tmux splits, mobile sshd) used to hard-clip every
    // ` label value · label value` row mid-word ("method brows",
    // "backe") and ellipsize the rotate commands into unusable
    // fragments. The view must reflow instead: kv rows stack, prose and
    // hints wrap, the store path keeps its tail, and every recovery
    // command survives.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Auth);
    app.router.auth_mut().set_login(AuthLoginView {
        provider: "openai".to_string(),
        method: "browser".to_string(),
        status: "connected".to_string(),
        detail: "credentials saved; validated against the provider".to_string(),
        store_path: "/Users/operator/.kuzushi/oauth-credentials.json".to_string(),
    });

    let width: u16 = 36;
    let area = ratatui::layout::Rect::new(0, 0, width, 50);
    let lines = auth_lines(&app, area);
    let texts: Vec<String> = lines.iter().map(line_text).collect();
    let rendered = texts.join("\n");

    for text in &texts {
        assert!(
            text.trim_end().chars().count() <= width as usize,
            "line overflows {width} cols and would clip: {text:?}"
        );
    }
    // kv values stack as whole words instead of clipping mid-word.
    assert!(rendered.contains("method    browser"));
    assert!(rendered.contains("status    connected"));
    // Prose wraps; the tail of the message is still readable.
    assert!(rendered.contains("provider"));
    assert!(rendered.contains("validated against"));
    // The store path keeps its useful tail, not the home-dir prefix.
    assert!(rendered.contains("oauth-credentials.json"));
    // Rotate hints wrap — the pasteable command survives in full.
    assert!(rendered.contains("re-launch kuzushi"));
    // Every recovery command is reachable; none hide behind an ellipsis.
    for command in [
        "auth login openai browser",
        "auth login github-copilot",
        "model <provider:id>",
        "back",
    ] {
        assert!(rendered.contains(command), "missing command: {command}");
    }
}

#[test]
fn home_view_shows_journey_rail_and_phase_chip_with_target() {
    // The engagement spine must be ambient: the home view carries the
    // Map → Scan → Review → Prove → Fix rail and the idle footer a
    // compact journey chip whenever a target is active.
    let dir = tempfile::tempdir().expect("temp target");
    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(dir.path().to_path_buf()));
    app.set_shell_view(ShellView::Home);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Map"), "rail shows map phase");
    assert!(rendered.contains("Scan"), "rail shows Scan phase");
    assert!(rendered.contains("Review"), "rail shows Review phase");
    assert!(rendered.contains("Prove"), "rail shows Prove phase");
    assert!(rendered.contains("Fix"), "rail shows fix phase");
    assert!(!rendered.contains("Hunt"), "legacy Hunt label is retired");
    assert!(
        !rendered.contains("Confirm"),
        "legacy Confirm label is retired"
    );
    assert!(rendered.contains("Map 1/5"), "footer phase chip");
    assert!(
        rendered.contains("type `next`"),
        "NEXT mechanics name the typed command"
    );
    assert!(
        rendered.contains("next · findings · options sast:scan"),
        "journey Home command list should expose next, findings, and tuning"
    );
}

#[test]
fn activity_view_collapses_tasks_pane_for_taskless_runs() {
    // A single-tool run registers no DAG tasks; the 40% TASKS pane would
    // only ever say "(no DAG tasks yet)" while the OUTPUT pane clips its
    // content. Collapse to a full-width OUTPUT pane instead.
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(ActivitySession::new("tool-1")));
    app.set_shell_view(ShellView::Activity);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(!rendered.contains("no DAG tasks yet"));
    assert!(!rendered.contains("TASKS"));
    assert!(rendered.contains("OUTPUT"));
    assert!(rendered.contains("no task rows — streaming tool output"));
}

#[test]
fn activity_view_names_the_running_tool_in_the_authoritative_header() {
    // The audit complaint: a taskless run showed an anonymous
    // "(waiting for trace events…)" against a static gallery and the
    // operator couldn't tell whether anything was happening. The header
    // names the tool with a ticking elapsed counter. Steps and footer avoid
    // repeating that identity; they own checklist navigation and controls.
    let backend = TestBackend::new(90, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_running_tool_for_test("threat-model:build");
    app.set_activity(Some(ActivitySession::new("tool-7b7fa744")));
    app.set_shell_view(ShellView::Activity);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("threat-model:build · running"));
    assert!(rendered.contains("TASKS"));
    assert!(!rendered.contains("waiting for trace events"));
    assert!(!rendered.contains("hover [j/k] to inspect a task"));
}

#[test]
fn run_focus_at_reported_96x89_size_is_side_by_side_without_shell_prompt() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut session = ActivitySession::new("run-wide");
    let mut task = DagTaskRow::queued(
        "context:build".to_string(),
        "context".to_string(),
        Vec::new(),
    );
    task.state = DagTaskState::Active;
    task.last_label = "Indexing repository".to_string();
    session.tasks.insert(task.task_id.clone(), task);
    apply_renderer_notice(&mut session, "Indexing repository");
    app.set_activity(Some(session));
    app.set_running_tool_for_test("context:build");
    app.set_shell_view(ShellView::Activity);
    app.set_input_mode(crate::InputMode::Navigate);
    let backend = TestBackend::new(96, 89);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rows = rendered_buffer_rows(terminal.backend().buffer());
    let task_row = rows
        .iter()
        .position(|row| row.contains("TASKS"))
        .expect("TASKS title");
    let output_row = rows
        .iter()
        .position(|row| row.contains("OUTPUT"))
        .expect("OUTPUT title");
    let rendered = rows.join("\n");

    assert_eq!(task_row, output_row, "wide panes must share a top row");
    assert!(rendered.contains("Indexing repository"), "{rendered}");
    assert!(!rendered.contains("NAVIGATION MODE"), "{rendered}");
}

#[test]
fn run_focus_stacks_sparse_output_at_120x36_to_preserve_long_task_labels() {
    let task_label = "Review authorization evidence across the complete external trust boundary";
    let mut session = ActivitySession::new("run-long-task");
    let mut task = DagTaskRow::queued(task_label.to_string(), "custom".to_string(), Vec::new());
    task.state = DagTaskState::Active;
    session.tasks.insert(task.task_id.clone(), task);
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rows = rendered_buffer_rows(terminal.backend().buffer());
    let tasks_row = rows.iter().position(|row| row.contains("TASKS")).unwrap();
    let output_row = rows.iter().position(|row| row.contains("OUTPUT")).unwrap();
    let rendered = rows.join("\n");

    assert!(tasks_row < output_row, "panes should stack: {rendered}");
    assert!(rendered.contains(task_label), "{rendered}");
}

#[test]
fn run_focus_keeps_useful_output_beside_a_measured_task_pane() {
    let task_label = "Review authorization evidence across trust boundaries";
    let mut session = ActivitySession::new("run-rich-output");
    let mut task = DagTaskRow::queued(task_label.to_string(), "custom".to_string(), Vec::new());
    task.state = DagTaskState::Active;
    session.tasks.insert(task.task_id.clone(), task);
    for index in 1..=6 {
        apply_renderer_notice(&mut session, &format!("Evidence batch {index} collected"));
    }
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rows = rendered_buffer_rows(terminal.backend().buffer());
    let tasks_row = rows.iter().position(|row| row.contains("TASKS")).unwrap();
    let output_row = rows.iter().position(|row| row.contains("OUTPUT")).unwrap();
    let rendered = rows.join("\n");

    assert_eq!(tasks_row, output_row, "panes should stay split: {rendered}");
    assert!(rendered.contains(task_label), "{rendered}");
    assert!(
        rendered.contains("Evidence batch 6 collected"),
        "{rendered}"
    );
}

#[test]
fn run_focus_wraps_a_long_authoritative_health_label_on_wide_screens() {
    let message =
        "Comparing authorization evidence from every external and internal trust boundary";
    let mut session = ActivitySession::new("run-long-health");
    let mut task = DagTaskRow::queued(
        "authorization-review".to_string(),
        "custom".to_string(),
        Vec::new(),
    );
    task.state = DagTaskState::Active;
    session.tasks.insert(task.task_id.clone(), task);
    apply_renderer_notice(&mut session, message);
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(session));
    app.set_running_tool_for_test("authorization-review");
    app.set_shell_view(ShellView::Activity);
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    assert!(rendered.contains("internal trust boundary"), "{rendered}");
    assert!(!rendered.contains("internal trust..."), "{rendered}");
}

#[test]
fn activity_view_renders_partial_terminal_outcome_from_run_summary() {
    let temp = tempfile::tempdir().unwrap();
    let mut summary = RunSummary::running(
        "run-partial-render",
        "scan",
        Some("sast:scan".to_string()),
        temp.path().display().to_string(),
    )
    .with_findings(Some(1));
    summary.status = "partial".to_string();
    summary.error = Some("triage stage did not complete".to_string());
    kuzushi_core::write_run_summary(temp.path(), &summary).unwrap();

    let backend = TestBackend::new(140, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_activity(Some(ActivitySession::new("run-partial-render")));
    app.set_shell_view(ShellView::Activity);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("⚠ run partial"), "{rendered}");
    assert!(rendered.contains("1 finding"), "{rendered}");
    assert!(
        rendered.contains("reason: triage stage did not complete"),
        "{rendered}"
    );
    assert!(!rendered.contains("clean"), "{rendered}");
}

#[test]
fn idle_activity_is_coherent_and_actionable_at_minimum_size() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Activity);
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let rendered = (0..12)
        .map(|y| buffer_row_text(buffer, 40, y))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(rendered.contains("RUN FOCUS · idle"), "{rendered}");
    assert!(rendered.contains("no active run"), "{rendered}");
    assert!(rendered.contains("scan"), "{rendered}");
    assert!(rendered.contains("run <tool>"), "{rendered}");
    assert!(rendered.contains("shell route"), "{rendered}");
    assert!(!rendered.contains("logs appear here du"), "{rendered}");
}

#[test]
fn completed_activity_prioritizes_outcome_and_one_pane_at_minimum_size() {
    let temp = tempfile::tempdir().unwrap();
    let mut summary = RunSummary::running(
        "scan-minimum-completed",
        "scan",
        Some("sast:scan".to_string()),
        temp.path().display().to_string(),
    )
    .with_findings(Some(7));
    summary.status = "completed".to_string();
    kuzushi_core::write_run_summary(temp.path(), &summary).unwrap();

    let mut session = ActivitySession::new("scan-minimum-completed");
    session.tasks.insert(
        "sast:scan".to_string(),
        crate::DagTaskRow::queued("sast:scan".into(), "scan".into(), Vec::new()),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);
    app.hydrate_active_view_blocking();
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("✓ run completed"), "{rendered}");
    assert!(rendered.contains("TASKS"), "{rendered}");
    assert!(!rendered.contains("OUTPUT"), "{rendered}");
}

#[test]
fn target_picker_renders_candidates_with_cursor_and_hints() {
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.target_picker_mut().open(vec![
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme"),
            label: ".".to_string(),
            hint: "git repo",
            scope: None,
        },
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme/api"),
            label: "api".to_string(),
            hint: "previous kuzushi target",
            scope: None,
        },
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme/libs/parser"),
            label: "libs/parser".to_string(),
            hint: "git submodule",
            scope: None,
        },
    ]);
    app.router.target_picker_mut().set_cursor(1);
    app.set_shell_view(ShellView::TargetPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CHOOSE A TARGET"));
    assert!(rendered.contains("git repo"));
    assert!(rendered.contains("▸ api"), "cursor marks the selected row");
    assert!(rendered.contains("previous kuzushi target"));
    assert!(rendered.contains("git submodule"));
    assert!(
        rendered.contains("Enter selects: api"),
        "selected target name"
    );
    assert!(
        rendered.contains("/work/acme/api"),
        "resolved selected path"
    );
    assert!(
        rendered.contains("target <path>"),
        "manual-path escape hatch"
    );
    assert!(
        rendered.contains("type `demo`"),
        "targetless/no-key escape hatch must advertise a live binding \
         (the `d` hotkey was retired)"
    );
}

#[test]
fn target_picker_windows_many_candidates_without_losing_consent_or_controls() {
    for (width, height) in [(80, 24), (60, 20)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let candidates = (1..=12)
            .map(|index| crate::app::TargetCandidate {
                path: std::path::PathBuf::from(format!("/work/acme/repo-{index:02}")),
                label: format!("repo-{index:02}"),
                hint: "git repo",
                scope: None,
            })
            .collect();
        app.router.target_picker_mut().open(candidates);
        app.router.target_picker_mut().set_cursor(11);
        app.set_shell_view(ShellView::TargetPicker);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("of 12 · ↑/↓ scroll"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("▸ repo-12"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Enter selects: repo-12"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("/work/acme/repo-12"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("Enter select"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            !rendered.contains("repo-01"),
            "{width}x{height}: {rendered}"
        );
    }
}

#[test]
fn ultra_compact_target_picker_keeps_selection_consent_and_controls_visible() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.target_picker_mut().open(vec![
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme"),
            label: ".".to_string(),
            hint: "git repo",
            scope: None,
        },
        crate::app::TargetCandidate {
            path: std::path::PathBuf::from("/work/acme/api"),
            label: "api".to_string(),
            hint: "git repo",
            scope: None,
        },
    ]);
    app.router.target_picker_mut().set_cursor(1);
    app.set_shell_view(ShellView::TargetPicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("▸ api"), "{rendered}");
    assert!(rendered.contains("Enter selects: api"), "{rendered}");
    assert!(rendered.contains("Enter select"), "{rendered}");
    assert!(!rendered.contains("d demo"), "{rendered}");
    assert!(rendered.contains("Esc browse"), "{rendered}");
}

#[test]
fn target_picker_prompt_footer_matches_first_escape_at_compact_and_wide_sizes() {
    for (width, height) in [(40, 12), (120, 36)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router
            .target_picker_mut()
            .open(vec![crate::app::TargetCandidate {
                path: std::path::PathBuf::from("/work/acme"),
                label: ".".to_string(),
                hint: "git repo",
                scope: None,
            }]);
        app.router
            .target_picker_mut()
            .set_focus(crate::app::PickerFocus::Prompt);
        app.set_shell_view(ShellView::TargetPicker);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(rendered.contains("command prompt active"), "{rendered}");
        assert!(rendered.contains("Esc return to picker"), "{rendered}");
        assert!(rendered.contains("Enter run"), "{rendered}");
        assert!(!rendered.contains("Esc browse"), "{rendered}");
    }
}

#[test]
fn model_picker_renders_offline_demo_escape_hatch() {
    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(std::path::PathBuf::from("/work/acme")));
    app.open_model_picker();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CHOOSE A MODEL"));
    assert!(rendered.contains("Target confirmed: acme"));
    assert!(rendered.contains("/work/acme"));
    assert!(rendered.contains("Try offline fixture"));
    assert!(rendered.contains("local/no auth"));
    assert!(!rendered.contains("d demo"));
}

#[test]
fn compact_model_picker_keeps_the_selected_model_visible() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-5.5".to_string());
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(std::path::PathBuf::from("/work/acme")));
    app.open_model_picker();
    app.router
        .model_picker_mut()
        .open(Some("anthropic:claude-opus-4-7"));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("of 10"), "{rendered}");
    assert!(rendered.contains("▸ Claude Opus"), "{rendered}");
    assert!(!rendered.contains("d demo"), "{rendered}");
    assert!(rendered.contains("Enter select"), "{rendered}");
}

#[test]
fn model_picker_discloses_retired_current_model_without_hiding_selection_or_keys() {
    for (width, height) in [(40, 12), (80, 24), (120, 36)] {
        let mut config = V2Config::default();
        config.model = Some("openai-codex:gpt-5.4".into());
        let mut app = ShellApp::new(config, None);
        app.open_model_picker();
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert!(
            rendered.contains("Current: openai-oauth:gpt-5.4"),
            "{width}x{height}: {rendered}"
        );
        assert!(rendered.contains("Retired for ChatGPT"), "{rendered}");
        let selected = rendered
            .lines()
            .find(|line| line.contains("▸ ") && line.contains("Terra"));
        assert!(selected.is_some(), "{rendered}");
        assert!(rendered.contains("Enter"), "{rendered}");
        assert!(rendered.contains("Esc keep"), "{rendered}");
        assert_eq!(app.config().model.as_deref(), Some("openai-codex:gpt-5.4"));
    }
}

#[test]
fn model_picker_discloses_unknown_current_model_as_unverified() {
    let mut config = V2Config::default();
    config.model = Some("openai:operator-custom-model".into());
    let mut app = ShellApp::new(config, None);
    app.open_model_picker();
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
    assert!(
        rendered.contains("Current: openai:operator-custom-model"),
        "{rendered}"
    );
    assert!(
        rendered.contains("availability is unverified"),
        "{rendered}"
    );
    assert!(rendered.contains("Esc keep"), "{rendered}");
}

#[test]
fn auth_picker_renders_selectable_offline_demo_row() {
    let backend = TestBackend::new(110, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(std::path::PathBuf::from("/work/acme")));
    app.open_auth_method_picker("openai".to_string());
    app.router.auth_picker_mut().set_cursor(2);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CHOOSE AUTH METHOD"));
    assert!(rendered.contains("Target confirmed: acme"));
    assert!(rendered.contains("/work/acme"));
    assert!(rendered.contains("▸ Offline demo"));
    assert!(rendered.contains("no key, model, or scanner binary"));
}

#[test]
fn ultra_compact_auth_picker_keeps_selected_method_and_valid_actions_visible() {
    for cursor in [0, 2] {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(std::path::PathBuf::from("/work/acme")));
        app.open_auth_method_picker("openai".to_string());
        app.router.auth_picker_mut().set_cursor(cursor);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = format!("{:?}", terminal.backend().buffer());

        assert!(
            rendered.contains("Offline demo"),
            "cursor {cursor}: {rendered}"
        );
        if cursor == 0 {
            assert!(rendered.contains("▸ API key"), "{rendered}");
            assert!(rendered.contains("Paste OPENAI_API_KEY"), "{rendered}");
            assert!(rendered.contains("type/paste key"), "{rendered}");
            assert!(!rendered.contains("d demo"), "{rendered}");
            assert!(!rendered.contains("q Setup"), "{rendered}");
        } else {
            assert!(rendered.contains("▸ Offline demo"), "{rendered}");
            assert!(
                rendered.contains("Enter runs the offline demo"),
                "{rendered}"
            );
            assert!(!rendered.contains("d demo"), "{rendered}");
            assert!(!rendered.contains("q Setup"), "{rendered}");
        }
    }
}

#[test]
fn file_picker_renders_filter_count_and_selected_file() {
    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::FilePicker);
    app.router.file_picker_mut().open(
        vec![
            "README.md".to_string(),
            "docs/design.md".to_string(),
            "src/main.rs".to_string(),
        ],
        false,
    );
    app.router.file_picker_mut().paste_query("des");

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("ATTACH A FILE"));
    assert!(rendered.contains("filter: des"));
    assert!(rendered.contains("1 shown"));
    assert!(rendered.contains("> docs/design.md"));
}

#[test]
fn partial_file_index_explains_how_to_attach_a_missing_path() {
    let backend = TestBackend::new(140, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::FilePicker);
    app.router
        .file_picker_mut()
        .open(vec!["src/main.rs".to_string()], true);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("partial index"));
    assert!(rendered.contains("paste exact path if missing"));
}

#[test]
fn home_view_without_target_has_no_journey_rail() {
    // No target → no engagement; home keeps the first-run guidance and
    // the rail stays out of the way.
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Home);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(!rendered.contains("Map ●"));
    assert!(!rendered.contains("phase:"));
    assert!(rendered.contains("quickstart"));
}

#[test]
fn auth_provider_rows_drop_detail_to_second_line_when_narrow() {
    // At full width the detail cell rides the same row; when the row
    // would overflow, the detail drops to an indented second line
    // instead of vanishing off the right edge.
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Auth);

    let area = ratatui::layout::Rect::new(0, 0, 36, 50);
    let rendered = auth_lines(&app, area)
        .iter()
        .map(line_text)
        .collect::<Vec<_>>()
        .join("\n");

    // The anthropic detail ("ANTHROPIC_API_KEY=…; oauth …") cannot fit
    // beside the 16-col name + 11-col status at width 36 — it must
    // appear on its own line rather than being clipped away.
    assert!(rendered.contains("ANTHROPIC_API_KEY="));
}

#[test]
fn transcript_log_line_renders_wall_clock_timestamp_when_present() {
    // `design/mockups/_shared.jsx::logLine` paints each transcript row
    // with a leading UTC `HH:MM:SSZ` in c-subtle. Verify the dated path
    // emits a labelled timestamp span styled subtle, before the
    // glyph + prefix + body.
    let line = transcript_line_dated(
        "tool",
        "ran semgrep:scan",
        false,
        // 14:32:14 UTC = 14*3600 + 32*60 + 14 = 52334 seconds into the day
        52_334,
    );
    let mut saw_subtle_time = false;
    let mut saw_glyph = false;
    for span in &line.spans {
        if span.content == "14:32:14Z" && span.style == theme::subtle() {
            saw_subtle_time = true;
        }
        if span.content.contains("⏵") {
            saw_glyph = true;
        }
    }
    assert!(saw_subtle_time, "subtle UTC wall time missing: {line:?}");
    assert!(saw_glyph, "transcript glyph missing: {line:?}");
}

#[test]
fn transcript_line_dated_skips_timestamp_when_zero() {
    // Synthetic transcript lines (built inside the renderer for
    // context-free hints) pass `time_secs = 0` and should produce no
    // leading timestamp — keeping those lines terse.
    let line = transcript_line_dated("tool", "synthetic", false, 0);
    for span in &line.spans {
        assert!(
            !span.content.contains(':') || !matches!(span.content.chars().next(), Some('0'..='9')),
            "unexpected timestamp on synthetic line: {span:?}"
        );
    }
}

#[test]
fn throttle_banner_uses_chip_style_per_mockup() {
    // `design/mockups/rate-limited.jsx` paints the throttle banner as
    // ` RATE LIMIT  <source> · <message>` with a warn-tinted chip
    // prefix and a muted message tail.  The Ratatui shell was emitting
    // `⚠ rate limit · <source> · <message>` in one warn span — the
    // chip-style prefix is what the operator's eye locks onto.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().throttle = Some(crate::app::ThrottleAdvisory {
        source: "anthropic".to_string(),
        message: "429 retry-after 14s".to_string(),
        since: std::time::Instant::now(),
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("RATE LIMIT"));
    assert!(rendered.contains("anthropic"));
    assert!(rendered.contains("429 retry-after"));
    assert!(
        !rendered.contains("⚠ rate limit"),
        "stale prose banner: {rendered}"
    );
}

#[test]
fn cost_cap_halt_row_drops_bracket_chrome() {
    // The cost-cap halt panel was the last place advertising bracketed
    // key chrome (`[c] continue past cap   [a] abort scan`).  The
    // mockups (e.g. `design/mockups/budget-stop.jsx`) use the same
    // unbracketed `<key> <hint>   <key> <hint>` shape as the keybind
    // footer.  Verify the panel renders the unbracketed form when the
    // budget is halted.
    let backend = TestBackend::new(80, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().budget_halt = Some(crate::app::BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("COST CAP HALT"));
    assert!(rendered.contains("continue past cap"));
    assert!(rendered.contains("abort scan"));
    assert!(
        !rendered.contains("[c]"),
        "stale bracket chrome: {rendered}"
    );
    assert!(
        !rendered.contains("[a]"),
        "stale bracket chrome: {rendered}"
    );
}

#[test]
fn cost_cap_halt_renders_compact_fallback_on_short_terminals() {
    let backend = TestBackend::new(80, 4);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().budget_halt = Some(crate::app::BudgetHalt {
        limit_usd: 1.0,
        spent_usd: 1.5,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("COST CAP: c=continue"));
    assert!(rendered.contains("a=abort"));
}

#[test]
fn module_detail_renders_options_when_stored_values_exist() {
    // `design/mockups/modules-detail.jsx::s2` shows OPTIONS · N as
    // a section.  Verify storing a value through `option_store`
    // surfaces the option in the panel.
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.option_store_mut().set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool("sast:scan".to_string()),
        "triage",
        serde_json::json!(true),
    );
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Module);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("OPTIONS"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("yes"));
}

#[test]
fn module_detail_lists_prompt_overrides_from_disk() {
    // `design/mockups/modules-detail.jsx::s4` shows PROMPTS · N
    // pulled from `.kuzushi/prompts/<module>/`.  Seed two prompt
    // files and verify both surface as detail rows.
    let tmp = tempfile::tempdir().unwrap();
    let prompts_root = tmp.path().join(".kuzushi/prompts/sast");
    std::fs::create_dir_all(&prompts_root).unwrap();
    std::fs::write(prompts_root.join("system.md"), "system prompt body").unwrap();
    std::fs::write(prompts_root.join("triage.md"), "triage prompt body").unwrap();

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.set_shell_view(ShellView::Module);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROMPTS"));
    assert!(rendered.contains("system"));
    assert!(rendered.contains("triage"));
}

#[test]
fn prompts_editor_renders_selected_prompt_stack() {
    let tmp = tempfile::tempdir().unwrap();
    let override_path = kuzushi_core::prompt_override_path(tmp.path(), "sast", "triage");
    std::fs::create_dir_all(override_path.parent().unwrap()).unwrap();
    std::fs::write(&override_path, "triage prompt body").unwrap();

    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.router.prompts_mut().set_cursor(0);
    app.set_shell_view(ShellView::PromptsEditor);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROMPT STACK"));
    assert!(rendered.contains("triage"));
    assert!(rendered.contains("project override"));
    assert!(rendered.contains("override active"));
    assert!(rendered.contains("sha256:"));
}

#[test]
fn prompt_document_renders_vim_mode_source_and_instructions() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = TestBackend::new(100, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    let prompt = app
        .prompt_spec_for_tool("agentic-sast:scan")
        .expect("agentic prompt descriptor");
    app.open_prompt_document_effect(PromptDocumentOpen {
        prompts: vec![prompt],
        prompt_index: 0,
        origin: ShellView::PlanningPicker,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PROMPT REVIEW"));
    assert!(rendered.contains("NORMAL"));
    assert!(rendered.contains("built-in"));
    assert!(rendered.contains("agentic SAST scanner"));
    assert!(rendered.contains(":wq save+setup"));
    assert!(rendered.contains(":q return"));
}

#[test]
fn trace_view_renders_steps_from_typed_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    write_lifecycle_notices(
        tmp.path(),
        "r-1",
        &[
            "Accepted a 4-task verification plan",
            "Fetched knowledge base entry a-04",
            "Comparing injection candidates",
            "Patch attempt blocked by policy",
        ],
    );

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.router.trace_mut().open("r-1");
    app.set_shell_view(ShellView::Trace);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TRACE · r-1"));
    assert!(rendered.contains("STEPS"));
    assert!(rendered.contains("Accepted a 4-task"));
    assert!(rendered.contains("Fetched knowledge"));
    assert!(rendered.contains("Comparing injection"));
    assert!(rendered.contains("Patch attempt blocked"));
}

#[test]
fn compact_trace_page_down_reaches_steps() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "r-compact-trace";
    write_lifecycle_notices(
        tmp.path(),
        run_id,
        &["Recon import started", "Recon import completed"],
    );
    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    // Paging is clamped to the app's measured viewport, as the live event
    // loop keeps it in step with the terminal.
    app.set_viewport(crate::TerminalViewport::new(60, 20));
    app.set_target(Some(tmp.path().to_path_buf()));
    seed_compact_scroll_findings(&mut app);
    app.router.trace_mut().open(run_id);
    app.set_shell_view(ShellView::Trace);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let first_page = format!("{:?}", terminal.backend().buffer());
    assert!(!first_page.contains("STEPS"), "{first_page}");

    app.set_input_mode(crate::InputMode::Navigate);
    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::empty(),
        ),
    );
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let second_page = format!("{:?}", terminal.backend().buffer());
    assert!(second_page.contains("STEPS"), "{second_page}");
    assert!(
        second_page.matches("activity").count() >= 2,
        "{second_page}"
    );
}

#[test]
fn compact_replay_page_down_reaches_aliases() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "r-compact-replay";
    let runs_root = ui_run_dir(Some(tmp.path()), run_id);
    std::fs::create_dir_all(&runs_root).unwrap();
    std::fs::write(
        runs_root.join("result.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "ok": true,
            "data": {
                "tool": "recon:import-httpx",
                "hosts": [{
                    "id": "h1", "workspaceId": "ws", "address": "192.0.2.10",
                    "hostname": "compact.example", "state": "alive"
                }],
                "services": [{
                    "id": "s1", "hostId": "h1", "port": 443, "proto": "tcp",
                    "name": "https", "state": "open"
                }],
                "notes": []
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let summary = RunSummary::running(
        run_id,
        "recon:import-httpx",
        None,
        tmp.path().display().to_string(),
    )
    .complete();
    kuzushi_core::write_run_summary(tmp.path(), &summary).unwrap();
    write_completed_lifecycle(tmp.path(), run_id, "Recon import completed");
    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(crate::TerminalViewport::new(60, 20));
    app.set_target(Some(tmp.path().to_path_buf()));
    seed_compact_scroll_findings(&mut app);
    app.router.replay_mut().open(run_id);
    app.set_shell_view(ShellView::Replay);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let first_page = format!("{:?}", terminal.backend().buffer());
    assert!(first_page.contains("REPLAY"), "{first_page}");
    assert!(!first_page.contains("ALIASES"), "{first_page}");

    app.set_input_mode(crate::InputMode::Navigate);
    let mut pages = vec![first_page];
    for _ in 0..6 {
        press_key(
            &mut app,
            crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::PageDown,
                crossterm::event::KeyModifiers::empty(),
            ),
        );
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        pages.push(format!("{:?}", terminal.backend().buffer()));
    }
    let all_pages = pages.join("\n");
    assert!(all_pages.contains("Recon import completed"), "{all_pages}");
    assert!(all_pages.contains("ALIASES"), "{all_pages}");
    assert!(all_pages.contains("F-0001"), "{all_pages}");
}

fn seed_compact_scroll_findings(app: &mut ShellApp) {
    *app.findings_mut() = (0..7)
        .map(|index| {
            Finding::new_tool(
                "secret-scan",
                &format!("rule-{index}"),
                &format!("src/secret-{index}.env"),
                index + 1,
                None,
                Severity::High,
                &format!("compact finding {index}"),
            )
        })
        .collect();
}

#[test]
fn trace_view_empty_when_no_lifecycle_items_exist() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.router.trace_mut().open("r-missing");
    app.set_shell_view(ShellView::Trace);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("TRACE · r-missing"));
    assert!(rendered.contains("no lifecycle items on disk"));
}

#[test]
fn replay_view_requires_run_json_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let canonical = ui_run_dir(Some(tmp.path()), "r-canonical");
    let missing = ui_run_dir(Some(tmp.path()), "r-missing");
    std::fs::create_dir_all(&canonical).unwrap();
    std::fs::create_dir_all(&missing).unwrap();
    std::fs::write(canonical.join("run.json"), r#"{"status":"completed"}"#).unwrap();

    let canonical_rendered = render_replay_for_target(tmp.path(), "r-canonical");
    assert!(canonical_rendered.contains("run.json"));

    let missing_rendered = render_replay_for_target(tmp.path(), "r-missing");
    assert!(missing_rendered.contains("MISSING ·"));
    assert!(missing_rendered.contains("run.json"));
}

#[test]
fn replay_view_surfaces_invalid_run_metadata_path() {
    let tmp = tempfile::tempdir().unwrap();
    let run_dir = ui_run_dir(Some(tmp.path()), "r-invalid");
    std::fs::create_dir_all(run_dir.join("run.json")).unwrap();

    let rendered = render_replay_for_target(tmp.path(), "r-invalid");

    assert!(rendered.contains("NOT A FILE ·"));
    assert!(rendered.contains("run.json"));
    assert!(!rendered.contains("run artefacts not on disk"));
}

fn render_replay_for_target(target: &std::path::Path, run_id: &str) -> String {
    let backend = TestBackend::new(140, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.to_path_buf()));
    app.router.replay_mut().open(run_id);
    app.set_shell_view(ShellView::Replay);
    app.hydrate_active_view_blocking();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    format!("{:?}", terminal.backend().buffer())
}

#[test]
fn patch_view_renders_rationale_diff_tests_and_guardrail_sections() {
    // `design/mockups/patch.jsx` shows RATIONALE / DIFF / TESTS /
    // GUARDRAIL.  Verify all four reach the buffer with diff lines
    // styled per kind (add → success, del → danger, ctx → muted).
    let backend = TestBackend::new(120, 48);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement.set_pending_patch(crate::app::PendingPatch {
            alias: "F-0001".to_string(),
            patch_run_id: "r-2113".to_string(),
            status: kuzushi_core::PatchStatus::Sound,
            rationale: "replace format!() concatenation with sqlx::query!() macro".to_string(),
            side_effect: Some("closes F-0001 (sqli)".to_string()),
            diff: "--- a/apps/api/orders.rs\n+++ b/apps/api/orders.rs\n@@ -138,9 +138,12 @@\n     let q = format!(\"SELECT * FROM orders WHERE id={}\", id);\n-    let row = sqlx::query(&q)\n+    let row = sqlx::query!(\n+        \"SELECT id FROM orders WHERE id = $1\",\n+        id\n+    )\n     .fetch_one(db)\n     .await?;".to_string(),
            tests: vec![
                ("orders::tests::rejects_sqli_payload".to_string(), "1 OR 1=1 → BadId".to_string()),
                ("orders::tests::happy_path_uuid".to_string(), "valid uuid → row".to_string()),
            ],
            guardrail: Some("approval.patches = human-required".to_string()),
            staged_at: Some(ui_run_artifact_relative_path("r-2113", "patch.diff")),
        });
    app.router.patch_mut().open("F-0001");
    app.set_shell_view(ShellView::Patch);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    // All four sections.
    assert!(rendered.contains("RATIONALE"));
    assert!(rendered.contains("DIFF"));
    assert!(rendered.contains("TESTS"));
    assert!(rendered.contains("GUARDRAIL"));
    // Rationale + side-effect.
    assert!(rendered.contains("sqlx::query!()"));
    assert!(rendered.contains("side-effect"));
    // Diff content + summary.
    assert!(rendered.contains("apps/api/orders.rs"));
    assert!(rendered.contains("@@"));
    assert!(rendered.contains("rejects_sqli_payload"));
    // Diff summary in the divider — at least one file + add count.
    assert!(rendered.contains("1 file"));
    // Tests row.
    assert!(rendered.contains("happy_path_uuid"));
    // Guardrail action row.
    assert!(rendered.contains("/patch apply"));
    // Staged-at footer.
    assert!(rendered.contains("staged at"));
}

#[test]
fn patch_view_empty_state_when_no_patch_pending() {
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.patch_mut().open("F-0042");
    app.set_shell_view(ShellView::Patch);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("PATCH · F-0042 · empty"));
    assert!(rendered.contains("∅"));
    assert!(rendered.contains("no patch staged"));
    assert!(rendered.contains("patch:finding"));
    assert!(rendered.contains(".kuzushi/v3/runs/"));
}

#[test]
fn patch_diff_summary_counts_files_adds_and_dels() {
    let summary = patch_diff_summary(
        "--- a/file1\n+++ b/file1\n@@ -1,3 +1,4 @@\n+added\n-removed\n ctx\n+added2",
    );
    assert_eq!(summary.files, 1);
    assert_eq!(summary.adds, 2);
    assert_eq!(summary.dels, 1);
}

#[test]
fn confirm_card_renders_tool_target_and_y_n_action_row() {
    // `design/mockups/confirm-dialog.jsx` paints CONFIRM gates with
    // a warn header, tool/target/rationale rows, and a y/Y/n/Esc/N action
    // row.  Verify each lands in the buffer when the gate is pending.
    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "curl https://refund.acme/api/internal/balances".to_string(),
        rationale: Some("verify F-0012 reachability".to_string()),
        allowlist: Some("refund.acme on project allowlist".to_string()),
        actor: Some("attacker".to_string()),
        remembered: false,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("CONFIRM"));
    assert!(rendered.contains("network egress"));
    assert!(rendered.contains("sandbox:run"));
    assert!(rendered.contains("curl https://refund.acme"));
    assert!(rendered.contains("verify F-0012"));
    assert!(rendered.contains("refund.acme on project allowlist"));
    assert!(rendered.contains("allow once"));
    assert!(rendered.contains("n/Esc"));
    assert!(rendered.contains("deny once"));
    assert!(rendered.contains("deny + add to denylist"));
}

#[test]
fn confirm_card_destructive_kind_renders_unconditional_refusal() {
    // Destructive verbs (`rm -rf`, `git push --force`, etc.) get a
    // RED header + REFUSED · destructive verb label + the
    // unconditional-refusal rule, no y/Y override available.
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::DestructiveVerb,
        tool: "shell:run".to_string(),
        target: "rm -rf .git".to_string(),
        rationale: None,
        allowlist: None,
        actor: Some("attacker".to_string()),
        remembered: false,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("REFUSED"));
    assert!(rendered.contains("destructive verb"));
    assert!(rendered.contains("rm -rf .git"));
    assert!(rendered.contains("always refused"));
    assert!(!rendered.contains("allow once"));
}

#[test]
fn descriptor_confirm_card_omits_unsupported_remembered_allow() {
    let backend = TestBackend::new(120, 22);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::DescriptorEffect,
        tool: "recon:nmap".to_string(),
        target: "127.0.0.1".to_string(),
        rationale: Some("declared ExternalAction effect".to_string()),
        allowlist: None,
        actor: None,
        remembered: false,
    });

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("allow once"));
    assert!(rendered.contains("deny + add to denylist"));
    assert!(!rendered.contains("allow + remember"));
}

#[test]
fn confirm_keys_resolve_pending_confirm_with_remember_flag() {
    // y/Y/n/N drive `resolve_confirm`; verify the resolver clears
    // the gate and threads the `remembered` flag through.
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let mut app = ShellApp::new(V2Config::default(), None);
    app.advisory_mut().pending_confirm = Some(crate::app::PendingConfirm {
        kind: crate::app::ConfirmKind::NetworkEgress,
        tool: "sandbox:run".to_string(),
        target: "curl x".to_string(),
        rationale: None,
        allowlist: None,
        actor: None,
        remembered: false,
    });
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::empty()),
    );
    assert!(app.advisory().pending_confirm.is_none());
    // The system log line records the outcome.
    assert!(app
        .log_lines()
        .iter()
        .any(|line| line.body.contains("allowed") && line.body.contains("remembered")));
}

#[test]
fn agent_chat_fold_for_next_turn_pushes_completed_turn_into_history() {
    // Sanity-check the helper that backs the multi-turn UX: a
    // completed turn should fold into history; an empty initial
    // state should leave history empty.
    use crate::app::AgentChatView;

    let initial = AgentChatView::default();
    let next = initial.fold_for_next_turn("first question".to_string());
    assert!(next.history.is_empty());
    assert_eq!(next.question, "first question");

    let prev = AgentChatView {
        recovery_note: None,
        partial_answer: String::new(),
        question: "first question".to_string(),
        answer: Some("first answer".to_string()),
        running: false,
        abort_requested: false,
        error: None,
        history: Vec::new(),
        run_id: None,
        started_secs: 0,
        screen_context_scope: None,
        thread_context_key: None,
        attached_turn_count: 0,
        auxiliary_read_only: false,
        failure_context: None,
        pending_failure_context: None,
    };
    let next2 = prev.fold_for_next_turn("second question".to_string());
    assert_eq!(next2.history.len(), 1);
    assert_eq!(next2.history[0].question, "first question");
    assert_eq!(next2.question, "second question");
}

#[test]
fn next_action_line_falls_back_to_primary_when_no_run_or_em_dash() {
    // Free-form NEXT hints (e.g. "Build the context snapshot with …")
    // should still render as warn glyph + primary body — no tool-name
    // accent, no muted suffix.
    let line = next_action_line(
        "Build the context snapshot with `context build` so SAST has structure to walk.",
        120,
    );
    assert!(line
        .spans
        .iter()
        .any(|s| s.style == theme::warn() && s.content.contains("▸ NEXT")));
    assert!(!line.spans.iter().any(|s| s.style == theme::accent()));
    assert!(!line.spans.iter().any(|s| s.style == theme::muted()));
}

#[test]
fn compact_finding_row_renders_alias_severity_and_location() {
    let line = compact_finding_row(
        "F-0001",
        "CRITICAL",
        SeverityTone::Critical,
        "sql injection via order_id concatenation",
        "apps/api/orders.rs:142",
        120,
    );
    let text = line_text(&line);
    assert!(text.contains("F-0001"));
    assert!(text.contains("CRITICAL"));
    assert!(text.contains("sql injection via order_id"));
    assert!(text.contains("apps/api/orders.rs:142"));
}

/// Information hierarchy: the title says what the finding IS and must own
/// the row; a deep path yields, keeping its useful `file.rs:line` tail
/// (left-truncated) instead of its repo-root prefix.
#[test]
fn compact_finding_row_title_survives_a_deep_path() {
    let line = compact_finding_row(
        "F-0002",
        "HIGH",
        SeverityTone::High,
        "heap write via attacker-length memcpy",
        "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs:123",
        100,
    );
    let text = line_text(&line);
    assert!(
        text.contains("heap write via attacker-length memcpy"),
        "full title must render: {text}"
    );
    assert!(
        text.contains("execution.rs:123"),
        "location tail must survive: {text}"
    );
    assert!(
        !text.contains("crates/kuzushi-core"),
        "root prefix yields before the tail does: {text}"
    );
    assert!(
        text.chars().count() <= 100,
        "row must not overflow its width: {}",
        text.chars().count()
    );
}

/// T6 sweep: every major view must render without panicking at degenerate
/// terminal sizes (1-cell, 1-row, 1-column) with wide (CJK), emoji, and
/// combining-mark content loaded — width math that slices bytes or counts
/// chars instead of columns breaks exactly here.
#[test]
fn views_survive_degenerate_geometry_with_unicode_content() {
    let views = [
        ShellView::Home,
        ShellView::Catalog,
        ShellView::Workbench,
        ShellView::Setup,
        ShellView::Report,
        ShellView::Activity,
        ShellView::Campaign,
        ShellView::Coverage,
        ShellView::Jobs,
        ShellView::Runs,
        ShellView::Logs,
        ShellView::Help,
        ShellView::Threat,
        ShellView::PromptsEditor,
        ShellView::Tune,
        ShellView::Auth,
        ShellView::Cost,
        ShellView::TargetPicker,
        ShellView::Quickstart,
        ShellView::BootSplash,
        ShellView::QuitConfirm,
    ];
    let sizes = [
        (1u16, 1u16),
        (2, 2),
        (5, 3),
        (80, 1),
        (1, 40),
        (33, 6),
        (120, 40),
    ];
    for view in views {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_error_notice("工具", "扫描失败 🚨 café ẍ 深いパス/评估.rs:42");
        app.set_throttle("anthropic", "429 · 再試行 14秒 👾");
        app.set_shell_view(view);
        for (columns, rows) in sizes {
            let backend = TestBackend::new(columns, rows);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render_app(frame, &app))
                .unwrap_or_else(|error| {
                    panic!("{view:?} failed to draw at {columns}x{rows}: {error}")
                });
        }
    }
}

#[test]
fn error_notice_banner_renders_above_throttle() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);
    app.set_error_notice("tool", "semgrep:scan failed");
    app.set_throttle("anthropic", "429 retry-after 14s");

    let backend = TestBackend::new(120, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();

    let error_row = banner_row(buffer, "ERROR").expect("ERROR chip present");
    let rate_row = banner_row(buffer, "RATE LIMIT").expect("RATE LIMIT chip present");
    assert!(error_row < rate_row, "error notice must sit above throttle");
}

#[test]
fn notice_banner_hidden_on_short_terminal() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Catalog);
    app.set_error_notice("tool", "boom");

    let backend = TestBackend::new(80, 4);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();

    assert!(
        banner_row(buffer, "ERROR").is_none(),
        "notice banner must be suppressed under the 5-row floor"
    );
}

fn banner_row(buffer: &Buffer, needle: &str) -> Option<u16> {
    for y in 0..buffer.area.height {
        let mut row = String::new();
        for x in 0..buffer.area.width {
            row.push_str(buffer[(x, y)].symbol());
        }
        if row.contains(needle) {
            return Some(y);
        }
    }
    None
}

// ── Phase Workbench ──────────────────────────────────────────────────────────

fn workbench_app_with_findings() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    *app.findings_mut() = vec![Finding::new_semgrep(
        "demo.sqli",
        "apps/api/orders.rs",
        12,
        Some(14),
        Severity::High,
        "sql injection via order_id",
    )];
    app
}

fn review_search_render_app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);
    let mut high = Finding::new_tool(
        "semgrep",
        "gateway/high",
        "src/auth/gateway.rs",
        12,
        None,
        Severity::High,
        "gateway ownership bypass",
    );
    high.dedup_key = Some("gateway-high".to_string());
    let mut low = Finding::new_tool(
        "semgrep",
        "gateway/low",
        "src/auth/cookie.rs",
        20,
        None,
        Severity::Low,
        "cookie scope is broad",
    );
    low.dedup_key = Some("gateway-low".to_string());
    let mut critical = Finding::new_tool(
        "systems-hunt",
        "gateway/critical",
        "src/rpc/proxy.rs",
        30,
        None,
        Severity::Critical,
        "proxy request crosses tenant boundary",
    );
    critical.dedup_key = Some("gateway-critical".to_string());
    app.set_findings(vec![high, low, critical]);
    app.router.workbench_mut().review_mut().search_query =
        "severity:critical,high source:semgrep".to_string();
    app
}

#[test]
fn review_search_filters_render_at_reference_sizes() {
    let app = review_search_render_app();
    for (width, height) in [(120, 36), (80, 24), (60, 20)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("review search terminal");
        terminal
            .draw(|frame| render_app(frame, &app))
            .expect("render filtered Review");
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

        for marker in [
            "1 of 3",
            "[severity:critical|high]",
            "[source:semgrep]",
            "gateway ownership bypass",
        ] {
            assert!(
                rendered.contains(marker),
                "Review {width}x{height} dropped {marker}: {rendered}"
            );
        }
    }
}

#[test]
fn review_search_plain_output_uses_the_same_filter_model() {
    let app = review_search_render_app();
    let rendered = render_plain_app(&app, 120);

    for marker in [
        "1 of 3",
        "[severity:critical|high]",
        "[source:semgrep]",
        "facets before search",
        "severity critical:1 high:1 low:1",
        "status open:3",
        "gateway ownership bypass",
    ] {
        assert!(
            rendered.contains(marker),
            "plain Review dropped {marker}: {rendered}"
        );
    }
}

#[test]
fn workbench_keystroke_to_paint_reuses_large_findings_projection() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_latency_app();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let initial = format!("{:?}", terminal.backend().buffer());
    assert!(initial.contains("▸F-0001"), "{initial}");

    let cache_key = crate::ui_view_models::visible_findings_cache_key(&app);
    let projection_before = app
        .workbench_cache()
        .borrow()
        .visible_findings(&cache_key)
        .expect("initial paint caches the visible projection");
    assert_eq!(projection_before.len(), 400);

    assert!(press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()),
    ));
    assert_eq!(app.router.findings().cursor(), 1);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();

    let painted = format!("{:?}", terminal.backend().buffer());
    assert!(painted.contains("▸F-0002"), "{painted}");
    assert!(!painted.contains("▸F-0001"), "{painted}");
    let projection_after = app
        .workbench_cache()
        .borrow()
        .visible_findings(&cache_key)
        .expect("navigation paint keeps the visible projection cached");
    assert!(std::sync::Arc::ptr_eq(
        &projection_before,
        &projection_after
    ));
}

#[test]
#[ignore = "wall-clock performance gate; run serially with pnpm test:performance"]
fn workbench_warmed_input_to_paint_p95_stays_within_budget() {
    const SAMPLE_COUNT: usize = 60;
    const P95_BUDGET: std::time::Duration = std::time::Duration::from_millis(50);

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_latency_app();
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    for index in 0..8 {
        workbench_input_to_paint_sample(&mut terminal, &mut app, index);
    }

    let mut samples = (0..SAMPLE_COUNT)
        .map(|index| workbench_input_to_paint_sample(&mut terminal, &mut app, index))
        .collect::<Vec<_>>();
    samples.sort_unstable();
    let p95 = samples[(SAMPLE_COUNT * 95).div_ceil(100) - 1];
    eprintln!("warmed Workbench input-to-paint p95={p95:?}, budget={P95_BUDGET:?}");

    assert!(
        p95 <= P95_BUDGET,
        "warmed Workbench input-to-paint p95 {p95:?} exceeded {P95_BUDGET:?}; samples={samples:?}"
    );
}

#[test]
fn workbench_prompt_burst_paints_exact_draft_with_cached_large_ledger() {
    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_latency_app();
    app.set_input_mode(crate::InputMode::Prompt);

    let draft = "typing-latency-0123456789-abcdefghijklmn";
    type_prompt_burst(&mut app, draft);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();

    assert_eq!(app.input(), draft);
    let painted = format!("{:?}", terminal.backend().buffer());
    assert!(painted.contains(draft), "{painted}");
}

#[test]
#[ignore = "wall-clock performance gate; run serially with pnpm test:performance"]
fn workbench_warmed_prompt_input_to_paint_p95_stays_within_budget() {
    const SAMPLE_COUNT: usize = 60;
    const SINGLE_KEY_BUDGET: std::time::Duration = std::time::Duration::from_millis(25);
    const BURST_BUDGET: std::time::Duration = std::time::Duration::from_millis(50);
    const BURST: &str = "typing-latency-0123456789-abcdefghijklmn";

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_latency_app();
    app.set_input_mode(crate::InputMode::Prompt);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    for _ in 0..8 {
        workbench_prompt_input_to_paint_sample(&mut terminal, &mut app, "x");
        workbench_prompt_input_to_paint_sample(&mut terminal, &mut app, BURST);
    }

    let single_key = prompt_input_p95(&mut terminal, &mut app, "x", SAMPLE_COUNT);
    let burst = prompt_input_p95(&mut terminal, &mut app, BURST, SAMPLE_COUNT);
    eprintln!(
        "warmed Workbench prompt-to-paint p95: single={single_key:?} (budget={SINGLE_KEY_BUDGET:?}), burst={burst:?} (budget={BURST_BUDGET:?})"
    );

    assert!(
        single_key <= SINGLE_KEY_BUDGET,
        "warmed single-key prompt-to-paint p95 {single_key:?} exceeded {SINGLE_KEY_BUDGET:?}"
    );
    assert!(
        burst <= BURST_BUDGET,
        "warmed prompt burst-to-paint p95 {burst:?} exceeded {BURST_BUDGET:?}"
    );
}

fn workbench_latency_app() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_viewport(TerminalViewport::new(120, 36));
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Review));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewQueue);
    app.set_input_mode(crate::InputMode::Navigate);
    app.set_findings(
        (0..400)
            .map(|index| {
                let mut finding = Finding::new_semgrep(
                    format!("latency.rule.{index:04}"),
                    "src/latency.rs",
                    index + 1,
                    None,
                    Severity::High,
                    format!("latency finding {index:04}"),
                );
                finding.fingerprint = format!("latency-fingerprint-{index:04}");
                finding
            })
            .collect(),
    );
    let ledger_counts = crate::ui_view_models::finding_ledger_counts(
        app.findings(),
        app.review_decisions(),
        app.findings().len(),
    );
    app.domain_mut().set_finding_ledger_counts(ledger_counts);
    app
}

fn prompt_input_p95(
    terminal: &mut Terminal<TestBackend>,
    app: &mut ShellApp,
    input: &str,
    sample_count: usize,
) -> std::time::Duration {
    let mut samples = (0..sample_count)
        .map(|_| workbench_prompt_input_to_paint_sample(terminal, app, input))
        .collect::<Vec<_>>();
    samples.sort_unstable();
    samples[(sample_count * 95).div_ceil(100) - 1]
}

fn workbench_prompt_input_to_paint_sample(
    terminal: &mut Terminal<TestBackend>,
    app: &mut ShellApp,
    input: &str,
) -> std::time::Duration {
    app.set_input("");
    let started = std::time::Instant::now();
    type_prompt_burst(app, input);
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    assert_eq!(app.input(), input);
    started.elapsed()
}

fn type_prompt_burst(app: &mut ShellApp, input: &str) {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    for ch in input.chars() {
        assert!(press_key(
            app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()),
        ));
    }
}

fn workbench_input_to_paint_sample(
    terminal: &mut Terminal<TestBackend>,
    app: &mut ShellApp,
    index: usize,
) -> std::time::Duration {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    let key = if index.is_multiple_of(2) { 'j' } else { 'k' };
    let started = std::time::Instant::now();
    assert!(press_key(
        app,
        KeyEvent::new(KeyCode::Char(key), KeyModifiers::empty()),
    ));
    terminal.draw(|frame| render_app(frame, app)).unwrap();
    started.elapsed()
}

fn phase_native_workbench_fixture(page: WorkbenchPage) -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().expect("phase cockpit target");
    let source = target.path().join("src/auth/login.rs");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source tree");
    std::fs::write(&source, "pub fn login(input: &str) { query(input); }\n")
        .expect("source fixture");

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.set_shell_view(ShellView::Workbench);
    app.router.workbench_mut().set_page(Some(page));
    app.router.workbench_mut().set_focus(page.primary_surface());

    if page != WorkbenchPage::Map {
        let mut finding = Finding::new_tool(
            "semgrep",
            "rust/sql-injection",
            "src/auth/login.rs",
            1,
            None,
            Severity::High,
            "attacker input reaches the database query",
        );
        finding.evidence = vec![FindingEvidence {
            kind: "source-sink".to_string(),
            file_path: finding.file_path.clone(),
            line: 1,
            snippet: "query(input)".to_string(),
            rationale: "request input reaches a query boundary".to_string(),
            confidence: 94,
            request_blob: None,
            response_blob: None,
        }];
        *app.findings_mut() = vec![finding.clone()];
        *app.selected_finding_mut() = Some(finding);
    }

    (target, app)
}

fn render_phase_workbench_for_test(page: WorkbenchPage, width: u16, height: u16) -> String {
    let (_target, app) = phase_native_workbench_fixture(page);
    render_phase_app(&app, width, height)
}

fn render_phase_app(app: &ShellApp, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("phase cockpit terminal");
    terminal
        .draw(|frame| render_app(frame, app))
        .expect("render phase cockpit");
    rendered_buffer_rows(terminal.backend().buffer()).join("\n")
}

fn render_zoomed_phase_pane(page: WorkbenchPage, surface: PhaseSurfaceId) -> String {
    let (_target, app) = phase_native_workbench_fixture(page);
    render_zoomed_phase_app(app, surface)
}

#[test]
fn ultra_compact_prove_keeps_status_next_and_proof_visible() {
    let rendered = render_phase_workbench_for_test(WorkbenchPage::Prove, 40, 12);

    assert_compact_prove_status(&rendered);
}

#[test]
fn ultra_compact_zoomed_prove_keeps_status_and_next_visible() {
    let (_target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Prove);
    app.router
        .workbench_mut()
        .toggle_zoom(PhaseSurfaceId::ProveStatus);

    let rendered = render_phase_app(&app, 40, 12);

    assert_compact_prove_status(&rendered);
    assert!(
        !rendered.contains("Tab pane · Z restore cockpit"),
        "{rendered}"
    );
    assert!(rendered.contains("ZOOM · PROVE"), "{rendered}");
}

fn pending_prove_result_fixture() -> (tempfile::TempDir, ShellApp) {
    let (target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Prove);
    let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
    let completed = kuzushi_core::workflow_attempts::PhaseAttemptCompleted::new(
        kuzushi_core::WorkflowPhase::Prove,
        vec!["verify-result-run".to_string()],
        snapshot.clone(),
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed,
    );
    let ledger = kuzushi_core::workflow_attempts::PhaseAttemptLedger::from_events([
        kuzushi_core::workflow_attempts::PhaseAttemptEvent::PhaseAttemptCompleted(completed),
    ])
    .expect("valid Prove result attempt");
    app.engagement
        .set_phase_attempt_projection(Some(snapshot), ledger);

    (target, app)
}

#[test]
fn pending_prove_result_yields_to_investigation_and_trace_then_returns() {
    use crate::TerminalViewport;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    for key in ['v', 't'] {
        for width in [40, 80] {
            let (_target, mut app) = pending_prove_result_fixture();
            app.set_input_mode(InputMode::Navigate);
            app.set_viewport(TerminalViewport::new(width, 24));
            assert!(press_key(
                &mut app,
                KeyEvent::new(KeyCode::Char(key), KeyModifiers::NONE)
            ));
            let rendered = render_phase_app(&app, width, 24);
            assert!(!rendered.contains("RESULT · selected"), "{key}: {rendered}");
            let label = if key == 'v' { "INVESTIGATE" } else { "TRACE" };
            assert!(rendered.contains(label), "{key}: {rendered}");
            assert!(press_key(
                &mut app,
                KeyEvent::new(
                    if key == 't' {
                        KeyCode::Char('t')
                    } else {
                        KeyCode::Esc
                    },
                    KeyModifiers::NONE
                )
            ));
            assert!(render_phase_app(&app, width, 24).contains("RESULT · selected"));
            assert!(app.input().is_empty());
        }
    }
}

#[test]
fn ultra_compact_legacy_prove_result_keeps_status_and_honest_next_visible() {
    let (_target, app) = pending_prove_result_fixture();

    let rendered = render_phase_app(&app, 40, 12);

    assert!(rendered.contains("Selected F-0001"), "{rendered}");
    assert!(
        rendered.contains("[●○○]") && rendered.contains("1src"),
        "{rendered}"
    );
    assert!(rendered.contains("STATUS candidate"), "{rendered}");
    assert!(rendered.contains("NEXT inspect result"), "{rendered}");
    assert!(rendered.find("F-0001") < rendered.find("STATUS candidate"));
    assert!(rendered.find("STATUS candidate") < rendered.find("NEXT inspect result"));
    assert!(rendered.contains("RESULT"), "{rendered}");
}

fn assert_compact_prove_status(rendered: &str) {
    assert!(rendered.contains("F-0001"), "{rendered}");
    assert!(rendered.contains("[●○○]"), "{rendered}");
    assert!(rendered.contains("1src"), "{rendered}");
    assert!(rendered.contains("STATUS candidate"), "{rendered}");
    assert!(rendered.contains("verify F-"), "{rendered}");

    let identity_pos = rendered.find("F-0001").expect("finding identity");
    let status_pos = rendered.find("STATUS candidate").expect("status strip");
    let next_pos = rendered.find("verify F-").expect("next action");
    assert!(identity_pos < status_pos, "{rendered}");
    assert!(status_pos < next_pos, "{rendered}");
}

fn render_zoomed_phase_app(mut app: ShellApp, surface: PhaseSurfaceId) -> String {
    app.router.workbench_mut().toggle_zoom(surface);
    render_phase_app(&app, 120, 36)
}

struct MissingArtifactContract {
    name: &'static str,
    render: fn() -> String,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
}

#[test]
fn phase_renderers_explain_missing_artifacts_without_inventing_data() {
    for case in missing_artifact_contracts() {
        let rendered = (case.render)();
        for marker in case.required {
            assert!(
                rendered.contains(marker),
                "{} missing {marker:?}: {rendered}",
                case.name
            );
        }
        for marker in case.forbidden {
            assert!(
                !rendered.contains(marker),
                "{} invented {marker:?}: {rendered}",
                case.name
            );
        }
    }
}

fn missing_artifact_contracts() -> [MissingArtifactContract; 3] {
    [
        MissingArtifactContract {
            name: "runtime proof",
            render: render_missing_runtime_proof,
            required: &["runtime proof pending", "verify F-0001"],
            forbidden: &["REPLAY"],
        },
        MissingArtifactContract {
            name: "verification trace",
            render: render_missing_verification_trace,
            required: &[
                "run verify-without-trace · trace unavailable",
                "verify F-0001",
            ],
            forbidden: &["REPLAY", "replay verify-without-trace"],
        },
        missing_contract(
            "fix diagrams",
            render_missing_fix_diagrams,
            &[
                "no exploit chain",
                "exploit-chain:scan",
                "no data-flow diagram",
                "threat-model:build",
            ],
        ),
    ]
}

fn missing_contract(
    name: &'static str,
    render: fn() -> String,
    required: &'static [&'static str],
) -> MissingArtifactContract {
    MissingArtifactContract {
        name,
        render,
        required,
        forbidden: &[],
    }
}

fn render_missing_runtime_proof() -> String {
    let (_target, app) = phase_native_workbench_fixture(WorkbenchPage::Prove);
    render_phase_app(&app, 120, 36)
}

fn render_missing_verification_trace() -> String {
    let (_target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Prove);
    let mut finding = app.findings()[0].clone();
    finding.scan_id = Some("scan-without-trace".to_string());
    finding.verification = Some(verification_without_trace());
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    render_zoomed_phase_app(app, PhaseSurfaceId::ProveReceipt)
}

fn verification_without_trace() -> kuzushi_core::PersistedVerification {
    let mut verification = crate::test_support::test_empirical_verification(3);
    verification.crash_evidence = Some("verification succeeded".to_string());
    verification.duration_ms = 42;
    verification.cost_usd = 0.01;
    verification.verification_run_id = Some("verify-without-trace".to_string());
    verification.verified_scan_id = Some("scan-without-trace".to_string());
    verification.created_at = "2026-07-10T00:00:00Z".to_string();
    verification
}

fn render_missing_fix_diagrams() -> String {
    let (_target, app) = phase_native_workbench_fixture(WorkbenchPage::Fix);
    render_plain_app(&app, 120)
}

/// Item: the Prove and Fix empty-state panels must name the digit that
/// actually reaches Review. `2` reaches Scan, which holds no finding to
/// choose, and "Hunt" is the retired name for Scan.
#[test]
fn empty_prove_and_fix_panels_route_the_operator_to_review() {
    let review_key = WorkbenchPage::Review.page_key().to_string();

    for page in [WorkbenchPage::Prove, WorkbenchPage::Fix] {
        let target = tempfile::tempdir().expect("finding-free target");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.set_shell_view(ShellView::Workbench);
        app.router.workbench_mut().set_page(Some(page));
        app.router.workbench_mut().set_focus(page.primary_surface());

        let rendered = render_phase_app(&app, 120, 36);

        assert!(!rendered.contains("open Hunt"), "{page:?}: {rendered}");
        assert_eq!(
            empty_panel_cta_key(&rendered, "open Review and choose a finding"),
            review_key,
            "{page:?}: {rendered}"
        );
    }
}

/// The key an `empty_state_panel` CTA row advertises for `label`.
fn empty_panel_cta_key(rendered: &str, label: &str) -> String {
    let row = rendered
        .lines()
        .find(|line| line.contains(label))
        .unwrap_or_else(|| panic!("no CTA row for {label}: {rendered}"));
    row.split('▸')
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn prove_and_fix_zoom_reach_every_reference_pane() {
    let cases = [
        (
            WorkbenchPage::Prove,
            PhaseSurfaceId::ProveStatus,
            "STATUS / NEXT",
        ),
        (
            WorkbenchPage::Prove,
            PhaseSurfaceId::ProveEvidence,
            "EVIDENCE",
        ),
        (
            WorkbenchPage::Prove,
            PhaseSurfaceId::ProveLadder,
            "PROOF LADDER",
        ),
        (
            WorkbenchPage::Fix,
            PhaseSurfaceId::FixCandidate,
            "BREAKDOWN REPORT",
        ),
        (
            WorkbenchPage::Fix,
            PhaseSurfaceId::FixRemediation,
            "REMEDIATION",
        ),
    ];

    for (page, pane, marker) in cases {
        let rendered = render_zoomed_phase_pane(page, pane);
        assert!(
            rendered.contains(marker),
            "{page:?} {pane:?} zoom dropped {marker}: {rendered}"
        );
    }
}

#[test]
fn unavailable_zoom_target_falls_back_to_truthful_primary_surface() {
    let prove = render_zoomed_phase_pane(WorkbenchPage::Prove, PhaseSurfaceId::ProveReceipt);
    assert!(prove.contains("ZOOM STATUS / NEXT"), "{prove}");
    assert!(!prove.contains("ZOOM PROOF"), "{prove}");

    let fix = render_zoomed_phase_pane(WorkbenchPage::Fix, PhaseSurfaceId::FixDfd);
    assert!(fix.contains("ZOOM REMEDIATION"), "{fix}");
    assert!(!fix.contains("ZOOM DFD"), "{fix}");
}

#[test]
fn prove_finding_zoom_keeps_selected_finding_header() {
    let rendered = render_zoomed_phase_pane(WorkbenchPage::Prove, PhaseSurfaceId::ProveStatus);

    assert!(rendered.contains("F-0001  HIGH"), "{rendered}");
    assert!(
        rendered.contains("attacker input reaches the database query"),
        "{rendered}"
    );
}

#[test]
fn rich_fix_reference_sizes_keep_phase_kanji_out_of_diagram_whitespace() {
    let _theme = theme::scoped_theme_for_test(theme::ThemeConfig {
        color_depth: theme::ColorDepth::TrueColor,
        ..theme::ThemeConfig::default()
    });

    for (width, height) in [(120, 36), (160, 48)] {
        let rendered = render_phase_workbench_for_test(WorkbenchPage::Fix, width, height);
        assert_eq!(
            rendered.matches('掛').count(),
            0,
            "Fix {width}x{height} leaked a decorative kanji into content \
             (the Fix backdrop no longer paints one): {rendered}"
        );
    }
}

#[test]
fn phase_native_fix_plain_output_routes_export_through_report() {
    let (_target, app) = phase_native_workbench_fixture(WorkbenchPage::Fix);

    let rendered = render_plain_app(&app, 120);

    for marker in ["BREAKDOWN REPORT", "ATTACK TREE", "DFD", "REMEDIATION"] {
        assert!(rendered.contains(marker), "missing {marker}: {rendered}");
    }
    assert!(
        rendered.contains("> report"),
        "Fix must route export through the dedicated Report surface: {rendered}"
    );
}

#[test]
fn run_focus_keeps_run_ownership_without_duplicate_phase_chrome() {
    let (_target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Map);
    let mut session =
        ActivitySession::for_phase("run-map-reference", kuzushi_core::WorkflowPhase::Map);
    let mut task = DagTaskRow::queued(
        "context:build".to_string(),
        "context".to_string(),
        Vec::new(),
    );
    task.state = DagTaskState::Active;
    task.started_at = Some(std::time::Instant::now());
    session.tasks.insert(task.task_id.clone(), task);
    session.tasks.get_mut("context:build").unwrap().last_label =
        "stage 3/6 · building repository inventory".to_string();
    apply_renderer_notice(&mut session, "stage 3/6 · building repository inventory");
    app.set_activity(Some(session));
    app.set_running_tool_for_test("context:build");
    app.set_shell_view(ShellView::Activity);
    app.set_input_mode(crate::InputMode::Navigate);

    for (width, height) in [(60, 20), (104, 61), (120, 36), (150, 90)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("activity terminal");
        terminal
            .draw(|frame| render_app(frame, &app))
            .expect("render activity phase cockpit");
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

        assert!(
            rendered.contains("RUN FOCUS"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            rendered.contains("0/1 done"),
            "{width}x{height}: {rendered}"
        );
        assert!(rendered.contains("TASKS"), "{width}x{height}: {rendered}");
        assert!(!rendered.contains("PHASE"), "{width}x{height}: {rendered}");
        assert!(
            rendered.contains("building repository inventory"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            !rendered.contains("view map"),
            "Activity must identify the run, not impersonate Workbench: {rendered}"
        );
        assert!(
            !rendered.contains("MAP · RECON") && !rendered.contains("TELEMETRY"),
            "Activity must not embed the full phase cockpit: {rendered}"
        );
        assert!(rendered.contains("OUTPUT"), "{width}x{height}: {rendered}");
    }

    let plain = render_plain_app(&app, 120);
    for marker in [
        "RUN FOCUS",
        "STEPS",
        "OUTPUT",
        "building repository inventory",
    ] {
        assert!(
            plain.contains(marker),
            "plain Run Focus missing {marker}: {plain}"
        );
    }
    assert!(!plain.contains("PHASE"), "{plain}");
    assert!(!plain.contains("MAP · RECON"), "{plain}");
    assert!(!plain.contains("TELEMETRY"), "{plain}");
    assert!(
        !plain.lines().any(|line| line.starts_with(" -- RUN -")),
        "Run Focus already owns the typed run projection: {plain}"
    );
}

#[test]
fn tall_run_focus_pins_quiet_tool_disclosure_in_the_authoritative_header() {
    let (_target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Map);
    let now = std::time::Instant::now();
    let mut session = ActivitySession::for_phase("stale-context", kuzushi_core::WorkflowPhase::Map);
    let mut task = DagTaskRow::queued(
        "context:build".to_string(),
        "context".to_string(),
        Vec::new(),
    );
    task.state = DagTaskState::Active;
    task.started_at = Some(now - std::time::Duration::from_secs(65));
    task.last_label = "stage 4/6 · mapping attack surface".to_string();
    session.tasks.insert(task.task_id.clone(), task);
    apply_renderer_notice(&mut session, "stage 4/6 · mapping attack surface");
    session.set_last_run_item_at_for_test(now - std::time::Duration::from_secs(65));
    app.set_activity(Some(session));
    app.set_running_tool_for_test("context:build");
    app.set_shell_view(ShellView::Activity);
    let backend = TestBackend::new(150, 90);
    let mut terminal = Terminal::new(backend).expect("tall Activity terminal");

    terminal
        .draw(|frame| render_app(frame, &app))
        .expect("render stale context Activity");
    let rows = rendered_buffer_rows(terminal.backend().buffer());
    let rendered = rows.join("\n");

    let warning_row = rows
        .iter()
        .position(|row| row.contains("TOOL QUIET"))
        .expect("pinned quiet-tool disclosure");
    assert!(
        warning_row < 6,
        "warning should remain in the header: {rendered}"
    );
    assert!(rendered.contains("current context:build"), "{rendered}");
    assert!(
        rows[warning_row].contains("last") && rows[warning_row].contains("stage 4/6"),
        "{rendered}"
    );
    assert!(rendered.contains("stage 4/6"), "{rendered}");
    assert!(!rendered.contains("view map"), "{rendered}");
}

#[test]
fn generic_activity_keeps_run_focus_panes_even_when_the_workspace_is_in_map() {
    let (_target, mut app) = phase_native_workbench_fixture(WorkbenchPage::Map);
    let mut session = ActivitySession::new("generic-run");
    let mut task = DagTaskRow::queued(
        "manual:read".to_string(),
        "manual read".to_string(),
        Vec::new(),
    );
    task.state = DagTaskState::Active;
    task.started_at = Some(std::time::Instant::now());
    session.tasks.insert(task.task_id.clone(), task);
    app.set_activity(Some(session));
    app.set_shell_view(ShellView::Activity);

    let backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(backend).expect("generic activity terminal");
    terminal
        .draw(|frame| render_app(frame, &app))
        .expect("render generic activity");
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    for marker in ["RUN FOCUS", "TASKS", "OUTPUT"] {
        assert!(rendered.contains(marker), "missing {marker}: {rendered}");
    }
    assert!(!rendered.contains("MAP · RECON"), "{rendered}");
    assert!(!rendered.contains("TELEMETRY"), "{rendered}");
}

#[test]
fn command_palette_overlay_keeps_workbench_context_and_selection_marker() {
    let backend = TestBackend::new(160, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_app_with_findings();
    app.open_command_palette();
    app.palette_input('s');

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("COMMAND PALETTE"), "{rendered}");
    assert!(rendered.contains('▸'), "{rendered}");
    assert!(rendered.contains("Kuzushi"), "{rendered}");
    assert!(rendered.contains("target:no target"), "{rendered}");

    let selection_bg = theme::selection().bg.unwrap();
    let selected_cells = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .filter(|cell| cell.bg == selection_bg)
        .count();
    assert!(
        selected_cells <= 96,
        "only the modal selection owns the accent background: {selected_cells}"
    );
}

#[test]
fn compact_command_palette_keeps_a_result_controls_and_truthful_prompt() {
    let backend = TestBackend::new(40, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.open_command_palette();
    for ch in "find".chars() {
        app.palette_input(ch);
    }

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    assert!(rendered.contains("COMMAND PALETTE"), "{rendered}");
    assert!(rendered.contains("› find"), "{rendered}");
    assert!(rendered.contains("▸ find"), "{rendered}");
    assert!(rendered.contains("Enter load"), "{rendered}");
    assert!(
        rendered.contains("type to filter · Enter load · Esc close"),
        "{rendered}"
    );
    assert!(!rendered.contains("kuzushi>"), "{rendered}");
}

#[test]
fn palette_over_onboarding_never_leaks_the_picker_title() {
    for (width, height) in [(80, 24), (40, 12)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::TargetPicker);
        app.open_command_palette();

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

        assert!(
            rendered.contains("COMMAND PALETTE"),
            "{width}x{height}: {rendered}"
        );
        assert!(
            !rendered.contains("CHOOSE A TARGET"),
            "{width}x{height}: {rendered}"
        );
    }
}

#[test]
fn system_overlays_clear_origin_body_but_preserve_shell_chrome() {
    for view in [
        ShellView::Keymap,
        ShellView::ThemePicker,
        ShellView::QuitConfirm,
    ] {
        let backend = TestBackend::new(140, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.open_options_for_test(crate::app::OptionsView {
            tool_name: "sast:scan".to_string(),
            filter: crate::app::OptionsFilter::Standard,
        });
        app.set_shell_view(view);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

        assert!(rendered
            .lines()
            .next()
            .unwrap_or_default()
            .contains("KUZUSHI"));
        assert!(!rendered.contains("disabledTasks"), "{view:?}: {rendered}");
        assert!(
            !rendered.contains("set <key> <value>"),
            "{view:?}: {rendered}"
        );
    }
}

#[test]
fn quit_overlay_uses_confirmation_prompt_instead_of_command_input() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_shell_view(ShellView::QuitConfirm);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");

    assert!(rendered.contains("y confirm · n/Esc stay"), "{rendered}");
    assert!(!rendered.contains("kuzushi>"), "{rendered}");
}

#[test]
fn keymap_overlay_scrolls_without_dangling_section_headings() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    for (width, height) in [(40, 12), (60, 20), (80, 24), (100, 30)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_viewport(crate::TerminalViewport::new(width, height));
        app.set_shell_view(ShellView::Workbench);
        app.set_shell_view(ShellView::Keymap);
        app.set_input_mode(crate::InputMode::Prompt);

        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let rendered = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert_keymap_sections_have_a_body(&rendered, width, height);

        press_key(
            &mut app,
            KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
        );
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let paged = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert_ne!(paged, rendered, "{width}x{height} PageDown did not move");
        assert_keymap_sections_have_a_body(&paged, width, height);

        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT),
        );
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let bottom = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        let bottom_document = bottom
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with('│'))
            .map(|line| line.trim_matches('│').trim())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            bottom_document.contains("effective action keymap"),
            "{width}x{height} did not reach the final control-map text: {bottom}"
        );
        assert!(bottom.contains("PgUp/PgDn scroll"), "{bottom}");
        assert_keymap_sections_have_a_body(&bottom, width, height);

        press_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
        let above_bottom = rendered_buffer_rows(terminal.backend().buffer()).join("\n");
        assert_ne!(
            above_bottom, bottom,
            "{width}x{height} k stayed trapped at tail"
        );
        assert_keymap_sections_have_a_body(&above_bottom, width, height);
    }
}

fn assert_keymap_sections_have_a_body(rendered: &str, width: u16, height: u16) {
    for (heading, first_row) in [
        ("── GLOBAL", "open help"),
        ("── NAVIGATION", "j  ·  k"),
        ("── DISPATCH", "/scan"),
        ("── LIFECYCLE", "/history"),
        ("── VIEW · Workbench", "Esc"),
    ] {
        if rendered.contains(heading) {
            assert!(
                rendered.contains(first_row),
                "{width}x{height} dangling {heading}: {rendered}"
            );
        }
    }
}

#[test]
fn atlas_selection_band_fills_the_available_row() {
    let line = selection_band("row", true, 24);
    let text = line
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert_eq!(display_width(&text), 24);
    assert!(text.starts_with(" ▸ row"));
}

#[test]
fn narrow_model_picker_preserves_complete_action_atoms() {
    let backend = TestBackend::new(60, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.open_model_picker();

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());
    assert!(rendered.contains("credentials needed"), "{rendered}");
    assert!(rendered.contains("OAuth login needed"), "{rendered}");
    assert!(rendered.contains("Enter select"), "{rendered}");
    assert!(!rendered.contains("needs..."), "{rendered}");
}

#[test]
fn system_overlay_uses_modal_frame_over_origin_view() {
    let backend = TestBackend::new(160, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = workbench_app_with_findings();
    app.set_shell_view(ShellView::ThemePicker);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("THEME"), "{rendered}");
    assert!(rendered.contains("Kuzushi"), "{rendered}");
    assert!(rendered.contains("│"), "{rendered}");
}

#[test]
fn workbench_top_bar_renders_compact_journey_phase_with_target() {
    let target = tempfile::tempdir().expect("temp target");
    let backend = TestBackend::new(140, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_target(Some(target.path().to_path_buf()));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("KUZUSHI"), "{rendered}");
    assert!(rendered.contains("target "), "{rendered}");
    assert!(rendered.contains("Viewing Map"), "{rendered}");
    assert!(!rendered.contains("phase:"), "{rendered}");
    assert!(rendered.contains("Map ●"), "{rendered}");
    assert!(rendered.contains("▸ NEXT"), "{rendered}");
    assert!(rendered.contains("PROJECT CONTEXT"), "{rendered}");
    assert!(
        rendered.contains("checking durable map artifacts"),
        "un-hydrated Map shows the neutral placeholder, not an evidence verdict: {rendered}"
    );
    assert!(rendered.contains("context:missing"), "{rendered}");
    assert!(rendered.contains("context build"), "{rendered}");
}

fn rendered_buffer_rows(buffer: &Buffer) -> Vec<String> {
    (0..buffer.area.height)
        .map(|y| buffer_row_text(buffer, buffer.area.width, y))
        .collect()
}

#[test]
fn workbench_lines_plain_shows_top_bar_findings_and_dfd_empty_hint() {
    let app = workbench_app_with_findings();
    let rendered = render_plain_app(&app, 110);

    // Top bar identity plus the complete Review phase projection.
    assert!(rendered.contains("Kuzushi"), "{rendered}");
    assert!(rendered.contains("F-0001"), "{rendered}");
    assert!(rendered.contains("FINDINGS"), "{rendered}");
    assert!(rendered.contains("SELECTED FINDING"), "{rendered}");
}

#[test]
fn fix_plain_shows_report_preview_counts() {
    let mut app = workbench_app_with_findings();
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Fix));

    let rendered = render_plain_app(&app, 110);

    assert!(rendered.contains("BREAKDOWN REPORT"), "{rendered}");
    assert!(
        rendered.contains("1 high · 1 findings · 0 terminal · 1 open"),
        "{rendered}"
    );
    assert!(
        rendered.contains("report sarif/all · preview only; no report written · 1/1"),
        "{rendered}"
    );
    assert!(rendered.contains("ATTACK TREE"), "{rendered}");
    assert!(rendered.contains("DFD"), "{rendered}");
    assert!(rendered.contains("REMEDIATION"), "{rendered}");
    assert!(rendered.contains("> report"), "{rendered}");
}

#[test]
fn prove_selected_finding_keeps_evidence_and_proof_readable() {
    let backend = TestBackend::new(180, 64);
    let mut terminal = Terminal::new(backend).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let source_path = temp.path().join("src/main/java/Demo.java");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    let source = (1..=50)
        .map(|line| {
            if line == 42 {
                "String sql = \"SELECT * FROM accounts WHERE id=\" + request.getParameter(\"id\");"
                    .to_string()
            } else {
                format!("// filler line {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&source_path, source).unwrap();
    let mut finding = Finding::new_semgrep(
        "demo.sqli",
        "src/main/java/Demo.java",
        42,
        Some(42),
        Severity::High,
        "Request parameter is concatenated into an SQL query string before prepareStatement(), so the prepared statement does not prevent SQL injection.",
    );
    finding.message = "The request parameter is attacker-controlled and is concatenated into the SQL text before prepareStatement is called.".to_string();
    finding.evidence = vec![FindingEvidence {
        kind: "source-sink".to_string(),
        file_path: finding.file_path.clone(),
        line: 42,
        snippet: "String sql = \"SELECT * FROM accounts WHERE id=\" + request.getParameter(\"id\");".to_string(),
        rationale: "Attacker-controlled source reaches SQL construction before the prepared statement boundary.".to_string(),
        confidence: 95,
        request_blob: None,
        response_blob: None,
    }];
    finding.identity_id = Some("fi_0123456789abcdef0123456789abcdef".to_string());
    finding.triage = Some(TriageOutcome {
        first_link: None,
        refute_reason: None,
        verdict: TriageVerdict::TruePositive,
        confidence: 0.95,
        rationale: "Operator confirmed the source-to-sink path.".to_string(),
        cost_usd: 0.0,
        cost_usd_exact: true,
        estimated_cost_usd: None,
    });
    finding.triaged_by = Some(TriageAuthor::Human);
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ReviewDetail);
    app.set_viewport(TerminalViewport::new(180, 64));
    app.set_target(Some(temp.path().to_path_buf()));
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Prove));

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("Viewing Prove"), "{rendered}");
    assert!(rendered.contains("next required Map"), "{rendered}");
    assert!(rendered.contains("STATUS / NEXT"), "{rendered}");
    assert!(rendered.contains("EVIDENCE"), "{rendered}");
    assert!(rendered.contains("PROOF"), "{rendered}");
    assert!(rendered.contains("Demo.java:42"), "{rendered}");
    assert!(rendered.contains("SELECT * FROM accounts"), "{rendered}");
    assert!(!rendered.contains("┌DFD"), "{rendered}");
    assert!(rendered.contains("F-0001  HIGH"), "{rendered}");
    assert!(rendered.contains("decision:confirmed"), "{rendered}");
    assert!(rendered.contains("[●○○]"), "{rendered}");
    assert!(rendered.contains("1 source(s)"), "{rendered}");
    assert!(rendered.contains("runtime proof pending"), "{rendered}");
    assert!(rendered.contains("verify F-0001"), "{rendered}");
    let status_pos = rendered.find("STATUS").expect("status section");
    let next_pos = rendered[status_pos..]
        .find("NEXT")
        .map(|offset| status_pos + offset)
        .expect("next section");
    let evidence_pos = rendered[next_pos..]
        .find("EVIDENCE")
        .map(|offset| next_pos + offset)
        .expect("evidence section");
    let proof_pos = rendered[next_pos..]
        .find("PROOF LADDER")
        .map(|offset| next_pos + offset)
        .expect("proof ladder");
    assert!(next_pos < evidence_pos, "{rendered}");
    assert!(next_pos < proof_pos, "{rendered}");
    assert!(!rendered.contains("proof state:"), "{rendered}");
    assert!(rendered.contains("source-sink"), "{rendered}");
    assert!(
        rendered.contains("Attacker-controlled source"),
        "{rendered}"
    );
}

#[test]
fn contextual_dfd_deck_renders_artifact_and_restores_workbench() {
    let temp = tempfile::tempdir().unwrap();
    let doc = serde_json::json!({
        "systemContext": "Operators use Sample to review requests and preserve approved records.",
        "dfd": {
            "nodes": [
                {
                    "id": "user",
                    "type": "external-entity",
                    "name": "Browser",
                    "description": "Collects operator requests",
                    "purpose": "Provides the operator surface",
                    "trustZone": "internet"
                },
                {
                    "id": "api",
                    "type": "process",
                    "name": "API server",
                    "description": "Processes review requests",
                    "purpose": "Applies the review policy",
                    "trustZone": "app-tier"
                }
            ],
            "flows": [
                {
                    "id": "f1",
                    "sourceId": "user",
                    "targetId": "api",
                    "description": "https"
                }
            ]
        }
    });
    let path = kuzushi_core::capabilities::persistent_threat_model_path(temp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

    let backend = TestBackend::new(150, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_target(Some(temp.path().to_path_buf()));
    app.router
        .workbench_mut()
        .set_page(Some(WorkbenchPage::Prove));
    app.router
        .workbench_mut()
        .set_focus(PhaseSurfaceId::ProveEvidence);
    app.set_input_mode(crate::InputMode::Navigate);
    app.hydrate_active_view_blocking();
    app.open_scene_to_page(crate::scene3d::VizPage::Dfd);

    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let rendered = format!("{:?}", terminal.backend().buffer());

    assert!(rendered.contains("DATA-FLOW DIAGRAM"), "{rendered}");
    assert!(rendered.contains("Browser"), "{rendered}");
    assert!(rendered.contains("API server"), "{rendered}");

    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Tab,
            crossterm::event::KeyModifiers::empty(),
        ),
    );
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    let summary = format!("{:?}", terminal.backend().buffer());
    assert!(summary.contains("SYSTEM SUMMARY"), "{summary}");
    assert!(summary.contains("EXECUTIVE SUMMARY"), "{summary}");
    assert!(summary.contains("COMPONENT TREE"), "{summary}");
    assert!(summary.contains("Applies the review policy"), "{summary}");
    assert_eq!(app.shell_view(), ShellView::Scene);

    press_key(
        &mut app,
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Esc,
            crossterm::event::KeyModifiers::empty(),
        ),
    );
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(wb_focus(&app), PhaseSurfaceId::ProveEvidence);
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Prove));
    assert_eq!(app.input_mode(), crate::InputMode::Navigate);
}

#[test]
fn phase_three_overlay_views_render_plain_surfaces() {
    let cases = [
        (ShellView::BootSplash, "break the form"),
        (ShellView::QuitConfirm, "CONFIRM SESSION EXIT"),
        (ShellView::ThemePicker, "THEME"),
        (ShellView::Keymap, "keymap"),
        (ShellView::UpdateAvailable, "UPDATE"),
    ];

    for (view, marker) in cases {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(view);
        let rendered = render_plain_app(&app, 120);
        assert!(
            rendered.contains(marker),
            "{marker} missing from {rendered}"
        );
        assert!(
            rendered.contains("KUZUSHI") || rendered.contains("break the form"),
            "{marker} missing shell identity: {rendered}"
        );
    }
}

#[test]
fn phase_four_interruption_views_render_plain_surfaces() {
    let cases = [
        (crate::app::InterruptionView::BudgetHardStop, "BUDGET CAP"),
        (crate::app::InterruptionView::BudgetStop, "BUDGET HARD STOP"),
        (crate::app::InterruptionView::NoBinary, "NO BINARY"),
        (crate::app::InterruptionView::NoModel, "NO MODEL CONFIGURED"),
        (crate::app::InterruptionView::NoPlugin, "NO PLUGIN"),
        (crate::app::InterruptionView::NetworkDown, "NETWORK DOWN"),
        (crate::app::InterruptionView::RateLimited, "RATE LIMITED"),
    ];

    for (view, marker) in cases {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.interruption_mut().open(view);
        app.set_shell_view(ShellView::Interruption);
        app.advisory_mut().budget_halt = Some(crate::app::BudgetHalt {
            limit_usd: 2.50,
            spent_usd: 2.75,
        });
        let rendered = render_plain_app(&app, 120);
        assert!(
            rendered.contains(marker),
            "{marker} missing from {rendered}"
        );
        assert!(
            rendered.contains("> try:"),
            "{marker} missing CTA: {rendered}"
        );
    }
}

#[test]
fn phase_five_committed_module_views_render_descriptor_details() {
    let cases = [
        ("agentic-sast", "agentic-sast:scan"),
        ("codeql", "codeql:scan"),
        ("dep-hygiene", "dep-hygiene:check"),
        ("iac-scan", "iac-scan:scan"),
        ("ndiff", "ndiff:fetch-cve"),
        ("randori", "randori:pasta"),
        ("recon", "recon:import"),
        ("sast", "sast:scan"),
        ("secret-scan", "secret-scan:scan"),
        ("semgrep", "semgrep:scan"),
        ("shinsa", "shinsa:scan"),
        ("taint-iris-next", "taint-iris-next:dataflow-plan"),
        ("tob", "tob:audit"),
        ("triage", "triage:run"),
        ("variant", "variant:hunt"),
        ("verify", "verify:finding"),
        ("vuln-scout", "vuln-scout:audit"),
        ("x-ray", "x-ray:run"),
    ];

    for (module_id, expected_tool) in cases {
        let mut app = ShellApp::new(V2Config::default(), None);
        let hidden = app
            .registry()
            .all_modules()
            .find(|module| module.metadata().id == module_id)
            .unwrap_or_else(|| panic!("{module_id} should be registered"))
            .is_hidden();
        app.set_focused_module(Some(module_id.to_string()));
        app.set_shell_view(ShellView::Module);

        let rendered = render_plain_app(&app, 120);

        assert!(
            rendered.contains("MODULE DETAIL"),
            "{module_id} fell back from module detail: {rendered}"
        );
        assert!(
            rendered.contains(module_id),
            "{module_id} missing from rendered module detail: {rendered}"
        );
        assert!(
            rendered.contains(expected_tool),
            "{expected_tool} missing from {module_id} module detail: {rendered}"
        );
        if hidden {
            assert!(
                rendered.contains("AVAILABILITY"),
                "{module_id} hidden module did not explain availability: {rendered}"
            );
            assert!(
                rendered.contains("deferred or gated"),
                "{module_id} hidden module did not render the deferred/gated status: {rendered}"
            );
        }
    }
}

/// #172: an unbuilt Map carries only its readiness card, and the generic
/// column solver stretched that card across the whole 124-column body while
/// its rows stopped near column 90. The card is now a width-capped centered
/// form, and its rows spend that width on the state and next action the
/// project model already carries.
#[test]
fn unbuilt_map_context_card_is_centered_and_carries_state_and_action() {
    let target = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Workbench);
    app.set_target(Some(target.path().to_path_buf()));

    let wide = render_phase_app(&app, 160, 48);
    let (left, right) = cockpit_pane_span(&wide, "PROJECT CONTEXT")
        .unwrap_or_else(|| panic!("no PROJECT CONTEXT card at 160x48:\n{wide}"));

    assert!(
        left >= 12,
        "the readiness card must be a centered form, not the whole body: \
         left rail at column {left}\n{wide}"
    );
    assert!(
        right - left < 100,
        "the readiness card must stay inside the centered-form cap: \
         columns {left}..={right}\n{wide}"
    );
    assert!(
        right >= 96,
        "the card's rows must fill the card instead of stopping near column 90: \
         rightmost painted column {right}\n{wide}"
    );
    assert!(wide.contains("root only"), "state cell missing:\n{wide}");
    assert!(wide.contains("▸ next"), "action cell missing:\n{wide}");
    assert!(
        wide.contains("▸ context build"),
        "action cell missing:\n{wide}"
    );

    let narrow = render_phase_app(&app, 80, 24);
    let (narrow_left, _) = cockpit_pane_span(&narrow, "PROJECT CONTEXT")
        .unwrap_or_else(|| panic!("no PROJECT CONTEXT card at 80x24:\n{narrow}"));

    assert_eq!(
        narrow_left, 0,
        "an 80-column terminal keeps the full-width card:\n{narrow}"
    );
    assert!(
        !narrow.contains("▸ context build"),
        "80 columns cannot afford the action column; the row must collapse:\n{narrow}"
    );
}

/// `(left rail column, rightmost painted column)` of a cockpit pane. Panes
/// carry a left border only, so the right edge is measured from the rows that
/// share the pane's rail, clipped to the pane so the context rail beside it
/// cannot inflate the reading.
fn cockpit_pane_span(rendered: &str, title: &str) -> Option<(usize, usize)> {
    const PANE_COLUMN_LIMIT: usize = 100;
    let rows: Vec<Vec<char>> = rendered.lines().map(|row| row.chars().collect()).collect();
    let banner = rows
        .iter()
        .position(|row| row.iter().collect::<String>().contains(title))?;
    let left = rows[banner].iter().position(|cell| *cell == '│')?;
    let right = rows[banner..]
        .iter()
        .take_while(|row| row.get(left) == Some(&'│'))
        .filter_map(|row| {
            row.iter()
                .take(left + PANE_COLUMN_LIMIT)
                .rposition(|cell| !cell.is_whitespace())
        })
        .max()?;
    Some((left, right))
}

/// Plain output projects the same receipt columns the Map card draws. The
/// shared plain sanitizer folds the rule and the action marker to ASCII, so a
/// scripted operator reads the state and next action without needing
/// box-drawing glyph support.
#[test]
fn plain_project_model_rows_carry_the_same_state_and_action_cells() {
    let target = tempfile::tempdir().expect("temp target");
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::ProjectModel);
    app.set_target(Some(target.path().to_path_buf()));

    let rendered = render_plain_app(&app, 120);

    assert!(rendered.contains("root only"), "state cell: {rendered}");
    assert!(rendered.contains("| > next"), "action cell: {rendered}");
    assert!(
        rendered.contains("| > context build"),
        "action cell: {rendered}"
    );
    assert!(
        !rendered.contains('│'),
        "plain output must not depend on box drawing: {rendered}"
    );
}
