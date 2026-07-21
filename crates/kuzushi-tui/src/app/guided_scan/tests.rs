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

fn persist_adequate_map_result(target: &std::path::Path, run_id: &str) {
    crate::test_support::record_indexed_run(
        target,
        run_id,
        "context:build",
        serde_json::json!({
            "ok": true,
            "status": "completed",
            "data": { "snapshot": { "filesIndexed": 1 } }
        }),
    );
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

#[test]
fn result_ready_attention_consumes_body_navigation_keys() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Map,
        vec!["run-map-1".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Completed,
    );
    append_phase_attempt_completed(target.path(), completed).unwrap();
    app.refresh_phase_attempt_projection();
    app.show_guided_phase(WorkflowPhase::Map);
    app.set_input_mode(crate::InputMode::Navigate);
    app.router.workbench_mut().set_focus(PhaseSurfaceId::MapDfd);
    let page = app.router.workbench().page();

    for key in [
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::BackTab,
            crossterm::event::KeyModifiers::SHIFT,
        ),
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('j'),
            crossterm::event::KeyModifiers::NONE,
        ),
    ] {
        assert!(app.reduce_key(key).handled);
    }

    assert_eq!(app.router.workbench().page(), page);
    assert_eq!(wb_focus(&app), PhaseSurfaceId::MapDfd);
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
