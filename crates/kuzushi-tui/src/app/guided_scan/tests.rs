fn wb_focus(app: &ShellApp) -> crate::ui_view_models::PhaseSurfaceId {
    app.router
        .workbench()
        .focus_for(crate::ui_view_models::active_workbench_page(app))
}
use super::*;
use crate::ui_view_models::PhaseSurfaceId;
use kuzushi_core::modules::OptionType;
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, PhaseAttemptCompleted, PhaseAttemptOutcome, PhaseTargetSnapshot,
};
use kuzushi_core::Severity;

fn persist_adequate_map_result(target: &std::path::Path, run_id: &str) {
    crate::test_support::record_indexed_run(
        target,
        run_id,
        "threat-model:build",
        serde_json::json!({
            "ok": true,
            "status": "completed",
            "data": { "snapshot": { "filesIndexed": 1 } }
        }),
    );
}

fn persist_unresolved_scan_result(target: &std::path::Path, run_id: &str) -> PhaseAttemptCompleted {
    use kuzushi_core::workflow_attempts::{
        append_phase_checkpoint_skipped, PhaseCheckpointSkipped,
    };

    append_phase_checkpoint_skipped(
        target,
        PhaseCheckpointSkipped::new(WorkflowPhase::Map, PhaseTargetSnapshot::capture(target)),
    )
    .unwrap();
    crate::test_support::record_indexed_run(
        target,
        run_id,
        "findings:import",
        serde_json::json!({
            "ok": true,
            "status": "completed",
            "data": {"count": 0}
        }),
    );
    crate::test_support::append_typed_attempt(
        target,
        WorkflowPhase::Scan,
        run_id,
        PhaseAttemptOutcome::Completed,
    )
}

fn app_with_open_guided_other() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.open_other();
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Map);
    app
}

fn type_guided_other(app: &mut ShellApp, text: &str) {
    for ch in text.chars() {
        let update = app.reduce_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(ch),
            crossterm::event::KeyModifiers::NONE,
        ));
        assert!(update.handled);
    }
}

fn assert_full_stopped_at_map(app: &ShellApp) {
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Map));
    assert!(app.engagement.guided_scan().is_none());
    assert!(app.log_lines().iter().any(|line| {
        line.prefix == "full"
            && line.body.contains("full pipeline complete at Map")
            && line.body.contains("phases.stop_after=map")
    }));
}

#[test]
fn numeric_option_always_offers_validated_other() {
    let spec = OptionSpec {
        name: "sample_limit".to_string(),
        option_type: OptionType::Int,
        description: "Maximum samples".to_string(),
        required: false,
        advanced: false,
        evasion: false,
        path_semantics: None,
        file_reference_semantics: None,
        default: Some(Value::from(200)),
        minimum: None,
        maximum: None,
        choices: Vec::new(),
        aliases: Vec::new(),
        deprecated_aliases: Vec::new(),
    };
    let choices = options::option_choices(&spec, Some(Value::from(200)));
    assert_eq!(choices[0].label, "Keep 200");
    assert!(matches!(
        choices.last().map(|choice| &choice.value),
        Some(GuidedOptionValue::Other)
    ));
}

#[test]
fn guided_questions_hide_unstructured_workflow_inputs() {
    let app = ShellApp::new(V2Config::default(), None);
    let spec = OptionSpec {
        name: "document".to_string(),
        option_type: OptionType::Json,
        description: "Internal handoff".to_string(),
        required: false,
        advanced: false,
        evasion: false,
        path_semantics: None,
        file_reference_semantics: None,
        default: None,
        minimum: None,
        maximum: None,
        choices: Vec::new(),
        aliases: Vec::new(),
        deprecated_aliases: Vec::new(),
    };

    assert!(!guided_option_is_visible(
        &app,
        PlanningTaskId::BuildThreatModel,
        &spec
    ));
}

#[test]
fn optional_option_without_a_value_offers_automatic_and_other() {
    let spec = OptionSpec {
        name: "target".to_string(),
        option_type: OptionType::Path,
        description: "Workspace path".to_string(),
        required: false,
        advanced: false,
        evasion: false,
        path_semantics: None,
        file_reference_semantics: None,
        default: None,
        minimum: None,
        maximum: None,
        choices: Vec::new(),
        aliases: Vec::new(),
        deprecated_aliases: Vec::new(),
    };

    let choices = options::option_choices(&spec, None);

    assert_eq!(choices[0].label, "Use automatic default");
    assert!(choices[0].recommended);
    assert_eq!(
        choices.last().map(|choice| choice.label.as_str()),
        Some("Other…")
    );
}

#[test]
fn option_question_offers_accepting_remaining_defaults() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.begin_options(
        WorkflowPhase::Map,
        vec![GuidedOptionTarget {
            task: PlanningTaskId::GatherRepoContext,
            option_name: "sampleLimit".to_string(),
        }],
    );
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Map);

    let model = app.guided_scan_question_model().unwrap();

    assert!(model.accept_remaining_defaults);
    assert_eq!(
        model.progress.as_deref(),
        Some("step 3 of 3 · option 1 of 1")
    );
}

#[test]
fn other_editor_captures_shift_modified_characters() {
    let mut app = app_with_open_guided_other();

    for ch in ['A', ':', '!'] {
        let update = app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(ch),
            crossterm::event::KeyModifiers::SHIFT,
        ));
        assert!(update.handled);
    }

    let model = app.guided_scan_question_model().unwrap();
    assert_eq!(model.other_draft, "A:!");
}

#[test]
fn other_editor_honors_ctrl_w_and_terminal_alt_backspace() {
    let mut app = app_with_open_guided_other();
    type_guided_other(&mut app, "alpha beta");

    let ctrl_w = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('w'),
        crossterm::event::KeyModifiers::CONTROL,
    ));
    assert!(ctrl_w.handled);
    assert_eq!(
        app.guided_scan_question_model().unwrap().other_draft,
        "alpha "
    );

    let alt_backspace = app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Backspace,
        crossterm::event::KeyModifiers::ALT,
    ));
    assert!(alt_backspace.handled);
    assert_eq!(app.guided_scan_question_model().unwrap().other_draft, "");
}

#[test]
fn multiline_other_paste_is_visible_lossless_and_does_not_submit() {
    let mut app = app_with_open_guided_other();

    let update = app.reduce_paste("first\r\nsecond");

    assert!(update.handled);
    let flow = app.engagement.guided_scan().unwrap();
    assert_eq!(flow.stage(), GuidedScanStage::MapRoute);
    assert_eq!(
        flow.expanded_other_draft().as_deref(),
        Some("first\nsecond")
    );
    let model = app.guided_scan_question_model().unwrap();
    assert!(model.other_open);
    assert!(model.other_draft.contains("paste #1"));
    assert!(!model.other_draft.contains('\n'));
    assert_eq!(model.other_cursor, model.other_draft.chars().count());
}

#[test]
fn other_option_is_visible_and_reaches_descriptor_prepared_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let target = GuidedOptionTarget {
        task: PlanningTaskId::GatherRepoContext,
        option_name: "sampleLimit".to_string(),
    };
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.begin_options(WorkflowPhase::Map, vec![target.clone(), target]);
    flow.open_other();
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Map);

    for ch in "321".chars() {
        app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(ch),
            crossterm::event::KeyModifiers::NONE,
        ));
    }
    assert_eq!(app.guided_scan_question_model().unwrap().other_draft, "321");

    app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let prepared = app
        .resolved_input_for_planning_task(PlanningTaskId::GatherRepoContext)
        .unwrap();
    assert_eq!(prepared.get("sampleLimit"), Some(&Value::from(321)));
    assert_eq!(
        app.guided_scan_question_model()
            .unwrap()
            .acknowledgement
            .as_deref(),
        Some("Accepted sample limit = 321")
    );
}

#[test]
fn invalid_integer_other_remains_visible_for_correction() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let target = GuidedOptionTarget {
        task: PlanningTaskId::GatherRepoContext,
        option_name: "sampleLimit".to_string(),
    };
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.begin_options(WorkflowPhase::Map, vec![target]);
    flow.open_other();
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Map);
    type_guided_other(&mut app, "12x");

    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let invalid = app.guided_scan_question_model().unwrap();
    assert!(invalid.other_open);
    assert_eq!(invalid.other_draft, "12x");
    assert!(invalid.error.is_some());

    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Backspace,
        crossterm::event::KeyModifiers::NONE,
    ));
    assert_eq!(app.guided_scan_question_model().unwrap().other_draft, "12");
}

#[test]
fn out_of_range_descriptor_other_remains_visible_for_correction() {
    let mut app = app_with_secret_scan_limit_question();
    type_guided_other(&mut app, "1");

    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let invalid = app.guided_scan_question_model().unwrap();
    assert!(invalid.other_open);
    assert_eq!(invalid.other_draft, "1");
    assert!(invalid.error.as_deref().unwrap().contains("at least 1024"));
    assert_eq!(
        app.engagement
            .option_override_value(PlanningTaskId::ScanSecrets, "maxFileBytes"),
        None
    );
}

#[test]
fn valid_secret_scan_other_reaches_canonical_prepared_input() {
    let mut app = app_with_secret_scan_limit_question();
    type_guided_other(&mut app, "12345");

    app.reduce_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let prepared = app
        .resolved_input_for_planning_task(PlanningTaskId::ScanSecrets)
        .unwrap();
    assert_eq!(prepared.get("maxFileBytes"), Some(&Value::from(12_345)));
}

fn app_with_secret_scan_limit_question() -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    let target = GuidedOptionTarget {
        task: PlanningTaskId::ScanSecrets,
        option_name: "maxFileBytes".to_string(),
    };
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.begin_options(WorkflowPhase::Scan, vec![target.clone(), target]);
    flow.open_other();
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Scan);
    app
}

#[test]
fn unsupported_route_other_stays_open_and_explains_the_contract() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let mut flow = GuidedScanFlow::new(GuidedScanStage::MapRoute);
    flow.open_other();
    flow.other_editor_mut()
        .unwrap()
        .insert_str_at_cursor("something unrelated");
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Map);

    app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let model = app.guided_scan_question_model().unwrap();
    assert!(model.other_open);
    assert!(model.error.unwrap().contains("could not apply that answer"));
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::MapRoute)
    );
}

#[test]
fn context_aware_progress_never_skips_a_visible_step() {
    assert_eq!(
        projection::module_selection_progress(WorkflowPhase::Map, false),
        "step 2 of 3"
    );
    assert_eq!(
        projection::option_progress(WorkflowPhase::Map, 1, 2, false),
        "step 3 of 3 · option 1 of 2"
    );
    assert_eq!(
        projection::module_selection_progress(WorkflowPhase::Map, true),
        "step 2 of 4"
    );
    assert_eq!(
        projection::option_progress(WorkflowPhase::Map, 1, 2, true),
        "step 4 of 4 · option 1 of 2"
    );
}

#[test]
fn module_selection_focuses_continue_and_c_advances() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.begin_guided_scan_questions();
    app.activate_map_route(0);

    let model = app.guided_scan_question_model().unwrap();
    assert!(model.options[model.cursor].label.starts_with("Continue →"));

    let update = app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('c'),
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(update.handled);
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::ContextPrerequisite)
    );
}

#[test]
fn space_does_not_advance_single_select_map_route() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.begin_guided_scan_questions();

    let update = app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(' '),
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(update.handled);
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::MapRoute)
    );
}

#[test]
fn space_toggles_only_a_focused_module_row() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.begin_guided_scan_questions();
    app.activate_map_route(0);
    app.edit_guided_flow(|flow| flow.set_cursor(0));
    let task = app.engagement.planning_picker().tasks()[0].id;
    let selected_before = app.engagement.planning_picker().selected().contains(&task);

    app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char(' '),
        crossterm::event::KeyModifiers::NONE,
    ));

    assert_ne!(
        app.engagement.planning_picker().selected().contains(&task),
        selected_before
    );
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::ModuleSelection(WorkflowPhase::Map))
    );
}

#[test]
fn module_other_adds_without_erasing_existing_selections() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let rows = [
        PlanningTaskId::ScanSecrets,
        PlanningTaskId::ScanSemgrep,
        PlanningTaskId::ScanCodeql,
    ]
    .into_iter()
    .map(|id| PlanningTaskRow {
        id,
        label: id.label(),
        tool_name: id.tool_name(),
        artifact_path: std::path::PathBuf::from("/tmp/audit-artifact"),
        artifact_state: PlanningArtifactState::Missing,
        artifact_modified: None,
        model_backed: id.is_model_backed(),
        required_cli: None,
        cli_available: true,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    })
    .collect::<Vec<_>>();
    app.engagement.planning_picker_mut().open(
        rows,
        [PlanningTaskId::ScanSecrets, PlanningTaskId::ScanSemgrep]
            .into_iter()
            .collect(),
    );
    let mut flow = GuidedScanFlow::new(GuidedScanStage::ModuleSelection(WorkflowPhase::Scan));
    flow.open_other();
    flow.other_editor_mut()
        .unwrap()
        .insert_str_at_cursor("CodeQL");
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Scan);

    app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let selected = app.engagement.planning_picker().selected();
    assert!(selected.contains(&PlanningTaskId::ScanSecrets));
    assert!(selected.contains(&PlanningTaskId::ScanSemgrep));
    assert!(selected.contains(&PlanningTaskId::ScanCodeql));
    let question = app.guided_scan_question_model().unwrap();
    assert!(!question.other_open);
    assert_eq!(
        question.acknowledgement.as_deref(),
        Some("Added CodeQL security scan · 3 selected")
    );
}

#[test]
fn unavailable_module_other_stays_open_without_partial_selection() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let codeql = PlanningTaskRow {
        id: PlanningTaskId::ScanCodeql,
        label: PlanningTaskId::ScanCodeql.label(),
        tool_name: PlanningTaskId::ScanCodeql.tool_name(),
        artifact_path: std::path::PathBuf::from("/tmp/audit-artifact"),
        artifact_state: PlanningArtifactState::Missing,
        artifact_modified: None,
        model_backed: false,
        required_cli: Some("codeql"),
        cli_available: false,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    };
    app.engagement
        .planning_picker_mut()
        .open(vec![codeql], BTreeSet::new());
    let mut flow = GuidedScanFlow::new(GuidedScanStage::ModuleSelection(WorkflowPhase::Scan));
    flow.open_other();
    flow.other_editor_mut()
        .unwrap()
        .insert_str_at_cursor("CodeQL");
    app.engagement.set_guided_scan(flow);
    app.show_guided_phase(WorkflowPhase::Scan);

    app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Enter,
        crossterm::event::KeyModifiers::NONE,
    ));

    let question = app.guided_scan_question_model().unwrap();
    assert!(question.other_open);
    assert_eq!(question.other_draft, "CodeQL");
    assert!(question
        .error
        .unwrap()
        .contains("requires `codeql` on PATH"));
    assert!(app.engagement.planning_picker().selected().is_empty());
}

#[test]
fn accept_defaults_key_launches_the_remaining_map_plan() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.begin_guided_scan_questions();
    app.activate_map_route(0);
    let continue_index = app.engagement.planning_picker().tasks().len();
    let _ = app.activate_module_selection(WorkflowPhase::Map, continue_index);
    let _ = app.accept_context_prerequisite();

    let update = app.reduce_guided_scan_key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('a'),
        crossterm::event::KeyModifiers::NONE,
    ));

    assert!(update.handled);
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::Running(WorkflowPhase::Map))
    );
}

#[test]
fn option_name_is_humanized_for_question_copy() {
    assert_eq!(
        presentation_copy::humanize_option_name("sample_limit"),
        "sample limit"
    );
    assert_eq!(
        presentation_copy::humanize_option_name("sampleLimit"),
        "sample limit"
    );
}

#[test]
fn map_route_copy_distinguishes_first_run_from_rerun() {
    let fresh = presentation_copy::map_route_options(false, false);
    let prior = presentation_copy::map_route_options(false, true);

    assert_eq!(fresh[0].label, "Run recommended Map modules");
    assert_eq!(prior[0].label, "Re-run recommended Map modules");
}

#[test]
fn rerun_reselects_cached_recommended_map_artifacts() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let row = PlanningTaskRow {
        id: PlanningTaskId::GatherRepoContext,
        label: PlanningTaskId::GatherRepoContext.label(),
        tool_name: PlanningTaskId::GatherRepoContext.tool_name(),
        artifact_path: std::path::PathBuf::from(".kuzushi/context-snapshot.json"),
        artifact_state: PlanningArtifactState::Cached,
        artifact_modified: None,
        model_backed: false,
        required_cli: None,
        cli_available: true,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    };
    app.engagement
        .planning_picker_mut()
        .open(vec![row], BTreeSet::new());

    app.mark_recommended_map_for_rebuild();

    assert!(app
        .engagement
        .planning_picker()
        .selected()
        .contains(&PlanningTaskId::GatherRepoContext));
    assert!(app
        .engagement
        .planning_picker()
        .rebuild()
        .contains(&PlanningTaskId::GatherRepoContext));
}

#[test]
fn guided_scan_routes_through_map_modules_and_context_question() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

    app.begin_guided_scan_questions();
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::MapRoute)
    );
    assert!(app
        .guided_scan_question_model()
        .unwrap()
        .options
        .iter()
        .any(|option| option.other));

    app.activate_map_route(0);
    let task_count = app.engagement.planning_picker().tasks().len();
    let _ = app.activate_module_selection(WorkflowPhase::Map, task_count);

    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::ContextPrerequisite)
    );
    let question = app.guided_scan_question_model().unwrap();
    assert!(question.prompt.contains("context has not been built"));
    assert_eq!(
        question.options.last().map(|row| row.label.as_str()),
        Some("Other…")
    );
}

#[test]
fn selecting_map_result_continues_into_scan_module_questions() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    persist_adequate_map_result(target.path(), "run-map-1");
    let completed = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "run-map-1",
        PhaseAttemptOutcome::Completed,
    );
    let attempt_id = completed.attempt_id.clone();
    app.refresh_phase_attempt_projection();
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Map,
        )));
    assert!(app.bind_guided_phase_result(WorkflowPhase::Map, attempt_id));
    app.show_guided_phase(WorkflowPhase::Map);
    assert!(
        app.guided_scan_question_model().is_none(),
        "selectable completions use the compact phase receipt, not a guided card"
    );

    let update = app.apply_phase_result_command(PhaseResultCommand::Continue);

    assert!(update.handled);
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::ModuleSelection(WorkflowPhase::Scan))
    );
    assert_eq!(
        app.guided_scan_question_model()
            .map(|question| question.header),
        Some("SCAN · MODULES".to_string())
    );
}

#[test]
fn full_pipeline_stops_cleanly_after_map_when_configured() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut config = V2Config::default();
    config.phases.stop_after = Some(kuzushi_core::GuidedPhase::Map);
    let mut app = ShellApp::new(config, Some(&workspace));
    persist_adequate_map_result(target.path(), "run-map-stop");
    let completed = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "run-map-stop",
        PhaseAttemptOutcome::Completed,
    );
    app.refresh_phase_attempt_projection();
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Map,
        )));
    assert!(app.bind_guided_phase_result(WorkflowPhase::Map, completed.attempt_id));
    app.show_guided_phase(WorkflowPhase::Map);

    let update = app.apply_phase_result_command(PhaseResultCommand::Continue);

    assert!(update.handled);
    assert_full_stopped_at_map(&app);
}

#[test]
fn full_pipeline_reusing_accepted_map_honors_map_stop() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut config = V2Config::default();
    config.phases.stop_after = Some(kuzushi_core::GuidedPhase::Map);
    persist_adequate_map_result(target.path(), "run-map-reused");
    let completed = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "run-map-reused",
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target.path(), &completed);
    let mut app = ShellApp::new(config, Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.begin_guided_scan_questions();
    assert!(app.has_accepted_map());

    let update = app.activate_map_route(0);

    assert!(update.handled);
    assert_full_stopped_at_map(&app);
}

#[test]
fn full_pipeline_empty_accepted_map_plan_honors_map_stop() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut config = V2Config::default();
    config.phases.stop_after = Some(kuzushi_core::GuidedPhase::Map);
    persist_adequate_map_result(target.path(), "run-map-empty-plan");
    let completed = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "run-map-empty-plan",
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target.path(), &completed);
    let mut app = ShellApp::new(config, Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.begin_guided_scan_questions();
    app.set_guided_stage(GuidedScanStage::ModuleSelection(WorkflowPhase::Map));
    app.engagement.planning_picker_mut().selected_mut().clear();
    assert!(build_execution_plan(
        app.engagement.planning_picker().tasks(),
        app.engagement.planning_picker().selected(),
        app.engagement.planning_picker().rebuild(),
    )
    .is_empty());

    let update = app.launch_guided_phase(WorkflowPhase::Map);

    assert!(update.handled);
    assert_full_stopped_at_map(&app);
}

#[test]
fn full_pipeline_clean_scan_hands_off_to_report() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let completed = persist_unresolved_scan_result(target.path(), "run-scan-clean");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.refresh_phase_attempt_projection();
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Scan,
        )));
    assert!(app.bind_guided_phase_result(WorkflowPhase::Scan, completed.attempt_id));
    app.show_guided_phase(WorkflowPhase::Scan);

    let update = app.apply_phase_result_command(PhaseResultCommand::Continue);

    assert!(update.handled);
    assert!(app.engagement.guided_scan().is_none());
    assert_eq!(app.shell_view(), ShellView::Report);
}

#[test]
fn full_pipeline_scan_with_findings_hands_off_to_review() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let completed = persist_unresolved_scan_result(target.path(), "run-scan-finding");
    let finding = kuzushi_core::Finding {
        fingerprint: "full-handoff-finding".to_string(),
        rule_id: "test/rule".to_string(),
        title: "review this finding".to_string(),
        severity: kuzushi_core::Severity::High,
        file_path: "src/lib.rs".to_string(),
        start_line: 1,
        tool: "test".to_string(),
        ..kuzushi_core::Finding::default()
    };
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    store.insert_finding("run-scan-finding", &finding).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_findings(vec![finding]);
    app.refresh_phase_attempt_projection();
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Scan,
        )));
    assert!(app.bind_guided_phase_result(WorkflowPhase::Scan, completed.attempt_id));
    app.show_guided_phase(WorkflowPhase::Scan);

    let update = app.apply_phase_result_command(PhaseResultCommand::Continue);

    assert!(update.handled);
    assert!(app.engagement.guided_scan().is_none());
    assert_eq!(app.shell_view(), ShellView::Workbench);
    assert_eq!(app.router.workbench().page(), Some(WorkbenchPage::Review));
}

#[test]
fn guided_attention_preserves_body_focus_and_scroll_from_mouse_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::MapRoute));
    app.show_guided_phase(WorkflowPhase::Map);
    app.router.workbench_mut().set_focus(PhaseSurfaceId::MapDfd);
    app.router
        .workbench_mut()
        .scroll_mut()
        .set(PhaseSurfaceId::MapDfd, 7);

    for kind in [
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        crossterm::event::MouseEventKind::ScrollDown,
    ] {
        let update = app.reduce_mouse(crossterm::event::MouseEvent {
            kind,
            column: 2,
            row: 2,
            modifiers: crossterm::event::KeyModifiers::NONE,
        });
        assert!(update.handled);
    }

    assert_eq!(wb_focus(&app), PhaseSurfaceId::MapDfd);
    assert_eq!(
        app.router.workbench().scroll().get(PhaseSurfaceId::MapDfd),
        7
    );
}

/// A non-success RESULT checkpoint collapses the body, so body cursor keys must not act
/// on the invisible body — but the checkpoint is NOT a modal: page and mode
/// navigation stay live under it (the G4 wedge fix; see
/// `unresolved_partial_result_does_not_wedge_page_navigation`).
#[test]
fn dominant_result_attention_consumes_body_navigation_keys() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    persist_adequate_map_result(target.path(), "run-map-accepted");
    let accepted = crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "run-map-accepted",
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target.path(), &accepted);
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-map-1".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Partial,
    );
    append_phase_attempt_completed(target.path(), completed).unwrap();
    app.refresh_phase_attempt_projection();
    *app.findings_mut() = vec![Finding::new_semgrep(
        "prior.rule",
        "src/lib.rs",
        1,
        None,
        Severity::High,
        "prior candidate",
    )];
    app.show_guided_phase(WorkflowPhase::Map);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router.workbench_mut().set_focus(PhaseSurfaceId::MapDfd);
    let page = app.router.workbench().page();

    assert!(
        app.reduce_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('j'),
            crossterm::event::KeyModifiers::NONE,
        ))
        .handled
    );
    assert_eq!(app.router.workbench().page(), page);
    assert_eq!(wb_focus(&app), PhaseSurfaceId::MapDfd);

    // Mode cycling keeps navigating under the checkpoint, and leaving the
    // page never silently resolves the attempt.
    assert!(
        app.reduce_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::BackTab,
            crossterm::event::KeyModifiers::SHIFT,
        ))
        .handled
    );
    assert_ne!(app.router.workbench().page(), page);
    assert!(app
        .engagement
        .unresolved_phase_attempt(WorkflowPhase::Map)
        .is_some());
}

#[test]
fn running_map_does_not_project_an_older_unresolved_attempt() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let old = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-map-old".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    );
    append_phase_attempt_completed(target.path(), old).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Map,
        )));
    app.show_guided_phase(WorkflowPhase::Map);

    assert!(app.guided_scan_question_model().is_none());
    app.set_shell_view(ShellView::Activity);
    assert!(app.guided_scan_question_model().is_none());
}

#[test]
fn bound_result_projects_only_its_exact_persisted_attempt() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    persist_adequate_map_result(target.path(), "run-map-exact");
    let exact = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-map-exact".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    );
    let exact_id = exact.attempt_id.clone();
    append_phase_attempt_completed(target.path(), exact).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::Running(
            WorkflowPhase::Map,
        )));
    app.show_guided_phase(WorkflowPhase::Map);

    assert!(app.bind_guided_phase_result(WorkflowPhase::Map, exact_id.clone()));
    assert_eq!(
        app.engagement.guided_scan().map(GuidedScanFlow::stage),
        Some(GuidedScanStage::AwaitingResult {
            phase: WorkflowPhase::Map,
            attempt_id: exact_id,
        })
    );
    assert!(app.guided_scan_question_model().is_some());
}

#[test]
fn guided_question_never_owns_non_workbench_input() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::MapRoute));
    app.set_shell_view(ShellView::Activity);

    assert!(app.guided_scan_question_model().is_none());
    assert!(!app.guided_scan_question_is_open());
}

#[test]
fn partial_map_result_copy_never_claims_modules_finished() {
    let prompt = presentation_copy::phase_result_prompt(
        WorkflowPhase::Map,
        PhaseAttemptOutcome::Partial,
        false,
    );

    assert!(prompt.contains("partial evidence"));
    assert!(!prompt.contains("finished"));
    assert!(!prompt.contains("continue to Scan"));
}

#[test]
fn blocked_result_copy_names_the_policy_stop_without_claiming_failure() {
    let prompt = presentation_copy::phase_result_prompt(
        WorkflowPhase::Scan,
        PhaseAttemptOutcome::Blocked,
        false,
    );

    assert!(prompt.contains("blocked before it could run"));
    assert!(prompt.contains("autonomy posture"));
    assert!(!prompt.contains("failed"));
    assert!(!prompt.contains("continue to Review"));
}

fn scan_picker_row(id: PlanningTaskId) -> PlanningTaskRow {
    PlanningTaskRow {
        id,
        label: id.label(),
        tool_name: id.tool_name(),
        artifact_path: std::path::PathBuf::from("/tmp/audit-artifact"),
        artifact_state: PlanningArtifactState::Action,
        artifact_modified: None,
        model_backed: id.is_model_backed(),
        required_cli: None,
        cli_available: true,
        blocker: None,
        cached_detail: None,
        last_attempt: None,
    }
}

fn write_seed_evidence(root: &std::path::Path) {
    let threat_path = kuzushi_core::capabilities::persistent_threat_model_path(root);
    std::fs::create_dir_all(threat_path.parent().unwrap()).unwrap();
    std::fs::write(
        threat_path,
        serde_json::json!({
            "dfd": {
                "nodes": [
                    {"id": "a", "name": "api", "trustZone": "app", "type": "process"},
                    {"id": "b", "name": "db", "trustZone": "data", "type": "data-store"}
                ],
                "flows": [{"id": "f", "sourceId": "a", "targetId": "b"}],
                "trustBoundaries": [{"id": "edge"}]
            },
            "threats": [{"id": "T-1"}, {"id": "T-2"}]
        })
        .to_string(),
    )
    .unwrap();
    let run_dir = crate::ui_view_models::ui_run_dir(Some(root), "run-seed");
    std::fs::create_dir_all(&run_dir).unwrap();
    let summary =
        kuzushi_core::RunSummary::running("run-seed", "tool", None, root.display().to_string());
    std::fs::write(
        run_dir.join("run.json"),
        serde_json::to_string(&summary).unwrap(),
    )
    .unwrap();
    std::fs::write(
        crate::ui_view_models::ui_latest_run_path(Some(root)),
        "run-seed",
    )
    .unwrap();
    std::fs::write(
        run_dir.join("recommendations.json"),
        serde_json::json!({
            "recommendations": [{
                "tool": "semgrep:scan",
                "priority": "high",
                "reason": "Falcon routes match semgrep coverage."
            }]
        })
        .to_string(),
    )
    .unwrap();
}

fn app_in_module_selection(root: &std::path::Path, phase: WorkflowPhase) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.to_path_buf()));
    app.engagement.planning_picker_mut().open(
        vec![scan_picker_row(PlanningTaskId::ScanSemgrep)],
        BTreeSet::new(),
    );
    app.engagement
        .set_guided_scan(GuidedScanFlow::new(GuidedScanStage::ModuleSelection(phase)));
    app.show_guided_phase(phase);
    app.hydrate_all_view_data_for_test();
    app
}

#[test]
fn scan_module_selection_is_seeded_by_threat_model_and_recommender() {
    let temp = tempfile::tempdir().unwrap();
    write_seed_evidence(temp.path());
    let app = app_in_module_selection(temp.path(), WorkflowPhase::Scan);

    let question = app.guided_scan_question_model().unwrap();

    assert_eq!(
        question.detail_lines.last().map(String::as_str),
        Some(
            "Lineage target rev:unknown · model [unstamped] — seeded by the threat model (2 \
             threat(s) · 1 trust boundary) and workspace signals."
        )
    );
    let semgrep = &question.options[0];
    assert!(
        semgrep
            .description
            .ends_with("— Falcon routes match semgrep coverage."),
        "{}",
        semgrep.description
    );
    assert!(semgrep.recommended);
    assert!(!semgrep.selected);
}

#[test]
fn scan_module_selection_degrades_honestly_without_seed_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let app = app_in_module_selection(temp.path(), WorkflowPhase::Scan);

    let question = app.guided_scan_question_model().unwrap();

    let provenance = question.detail_lines.last().unwrap();
    assert!(
        provenance.contains("generic engine defaults"),
        "{provenance}"
    );
    assert!(provenance.contains("Run Map"), "{provenance}");
    assert!(!question.options[0].recommended);
}

#[test]
fn map_module_selection_stays_unseeded() {
    let temp = tempfile::tempdir().unwrap();
    write_seed_evidence(temp.path());
    let app = app_in_module_selection(temp.path(), WorkflowPhase::Map);

    let question = app.guided_scan_question_model().unwrap();

    assert_eq!(question.detail_lines.len(), 1);
    assert!(!question.detail_lines[0].contains("Seeded"));
}
