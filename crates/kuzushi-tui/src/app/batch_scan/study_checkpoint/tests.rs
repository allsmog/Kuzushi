use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{
    session_transcript::{default_sessions_root, SessionMetadata, SessionTranscriptStore},
    V2Config,
};
mod prepared;

fn shell(target: &std::path::Path, home: &std::path::Path) -> ShellApp {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.canonicalize().unwrap()));
    let recorder = SessionTranscriptStore::from_root(default_sessions_root(home))
        .start(SessionMetadata::new("shell", home))
        .unwrap();
    app.attach_session_transcript(recorder);
    app.open_batch_scan_config(None);
    settle(&mut app);
    app
}

fn settle(app: &mut ShellApp) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        app.drain_study_checkpoints();
        let runtime = &app.runtime_state.study_checkpoints;
        if !runtime.has_pending() && runtime.recovery.is_none() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Study checkpoint did not settle"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn fill(app: &mut ShellApp, label: &str) {
    let config = app
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    config.study.scan_input = Some(
        serde_json::json!({"tasks":["semgrep"],"taskMode":"manual","threatModelRef":null,"triage":false,"verify":false,"patch":false}),
    );
    config.study.matrix.cases = vec![
        ContextCaseInput {
            id: "baseline".into(),
            label: label.into(),
            passes: 2,
            threat_model_ref: serde_json::Value::Null,
        },
        ContextCaseInput {
            id: "candidate".into(),
            label: "Candidate".into(),
            passes: 3,
            threat_model_ref: serde_json::Value::Null,
        },
    ];
    config.study.matrix.baseline_case_id = Some("baseline".into());
    config.study.matrix.open = true;
    config.study.matrix.cursor = 1;
    config.study.max_provider_calls = Some(7);
    config.study.protected_review_calls = Some(2);
    app.checkpoint_study_choices();
    settle(app);
}

fn key(app: &mut ShellApp, code: KeyCode) {
    app.handle_batch_config_key(KeyEvent::new(code, KeyModifiers::NONE))
        .unwrap();
}

#[test]
fn restart_restores_case_baseline_passes_and_partial_unicode_field_without_authority() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    fill(&mut app, "Baseline");
    let investigation = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .investigation_id
        .clone();
    key(&mut app, KeyCode::Char('n'));
    app.capture_context_case_name_paste(" α東京");
    key(&mut app, KeyCode::Home);
    key(&mut app, KeyCode::Right);
    settle(&mut app);
    let saved = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .clone();
    assert!(app.study_choices_checkpointed());
    let mut next = shell(target.path(), home.path());
    assert!(matches!(
        next.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Choices { .. }
    ));
    assert!(next.capture_context_case_name_paste("must not enter the composer") == false);
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let restored = next.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(restored.study.matrix.cases, saved.study.matrix.cases);
    assert_eq!(
        restored.study.matrix.name_edit,
        saved.study.matrix.name_edit
    );
    assert_eq!(restored.study.matrix.cursor, 1);
    assert_eq!(
        restored.study.matrix.baseline_case_id.as_deref(),
        Some("baseline")
    );
    assert_eq!(restored.study.investigation_id, investigation);
    assert_eq!(restored.study.max_provider_calls, Some(7));
    assert!(restored.study.plan_identity().is_none());
    assert!(!restored.study.approved());
    assert!(!next.has_running_work());
    assert!(!target.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn independent_drafts_stay_selectable_and_explicit_clear_resolves_only_adopted_hash() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    fill(&mut first, "First");
    let mut second = shell(target.path(), home.path());
    key(&mut second, KeyCode::Char('n'));
    fill(&mut second, "Second");
    let store = second
        .runtime_state
        .study_checkpoints
        .binding
        .as_ref()
        .unwrap()
        .0
        .clone();
    let mut third = shell(target.path(), home.path());
    let StudyDraftRecovery::Choices { drafts, .. } = &third
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .draft_recovery
    else {
        panic!("drafts required")
    };
    assert_eq!(drafts.len(), 2);
    let selected = drafts
        .iter()
        .position(|draft| draft.cases().iter().any(|c| c.0 == "Second"))
        .unwrap();
    if let StudyDraftRecovery::Choices { cursor, .. } = &mut third
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap()
        .draft_recovery
    {
        *cursor = selected;
    }
    key(&mut third, KeyCode::Enter);
    settle(&mut third);
    key(&mut third, KeyCode::Char('c'));
    settle(&mut third);
    let remaining = persistence::recover(&store, &target.path().canonicalize().unwrap()).unwrap();
    assert_eq!(remaining.len(), 2);
    assert_eq!(
        remaining
            .iter()
            .filter(|r| r.record.snapshot.as_ref().unwrap().cases.is_empty())
            .count(),
        1
    );
    assert_eq!(
        remaining
            .iter()
            .filter(|r| r.cases().iter().any(|c| c.0 == "First"))
            .count(),
        1
    );
    assert!(!third.study_checkpoint_pending());
}

#[test]
fn malformed_or_foreign_records_cannot_grant_jobs_model_or_allowance() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    fill(&mut app, "Baseline");
    let state = app
        .runtime_state
        .study_checkpoints
        .states
        .values()
        .next()
        .unwrap();
    let mut value = serde_json::to_value(&state.record).unwrap();
    for key in ["jobs", "allowance", "runtime", "model"] {
        value[key] = serde_json::json!(true);
        assert!(serde_json::from_value::<StudyCheckpointRecord>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove(key);
    }
    let file = EditorCheckpointFile {
        record_id: uuid::Uuid::new_v4().to_string(),
        bytes: serde_json::to_vec(&state.record).unwrap(),
        sha256: "a".repeat(64),
    };
    assert!(persistence::decode(file, &target.path().canonicalize().unwrap()).is_err());
}

#[test]
fn recovery_controls_and_selection_remain_visible_at_six_sizes_and_in_plain_output() {
    use ratatui::{backend::TestBackend, Terminal};
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    fill(&mut first, "Baseline");
    let mut app = shell(target.path(), home.path());
    for (width, height) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
        app.reduce_resize(width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::renderer::render_app(frame, &app))
            .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        for text in [
            "RECOVER STUDY DRAFT",
            "▸",
            "2 cases",
            "5 passes",
            "Enter restore",
            "Esc back",
        ] {
            assert!(screen.contains(text), "{width}x{height}: {text}");
        }
    }
    let plain = crate::renderer::render_plain_app(&app, 40);
    assert!(plain.contains("Enter restore"));
    assert!(!plain.contains('\u{1b}'));
}

#[cfg(unix)]
#[test]
fn failed_write_keeps_session_choices_and_honest_exit_warning() {
    use std::os::unix::fs::symlink;
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    symlink(
        home.path().join("elsewhere"),
        home.path().join(".kuzushi/v3/study-drafts"),
    )
    .unwrap();
    fill(&mut app, "Uncheckpointed");
    assert!(app.study_choices_not_checkpointed());
    assert!(app.study_checkpoint_note().unwrap().contains("not saved"));
    let quit = format!("{:?}", crate::ui_view_models::quit_confirm_model(&app));
    assert!(quit.contains("NOT SAVED"));
    assert!(!quit.contains("RECOVERABLE DRAFTS"));
    let mut next = shell(target.path(), home.path());
    assert!(matches!(
        next.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Failed(_)
    ));
    key(&mut next, KeyCode::Esc);
    assert!(!next.batch_config_open());
}

#[test]
fn recovered_investigation_retains_unresolved_accounting_and_requires_new_plan() {
    use kuzushi_core::allowance::{
        AllowanceApprovalV1, AllowanceCall, AllowanceLimits, InvestigationWork,
    };
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    fill(&mut first, "Accounted");
    let id = first
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study
        .investigation_id
        .clone();
    let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
    workspace.ensure_state_dir().unwrap();
    let ledger = kuzushi_core::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: id.clone(),
            expected_revision: 0,
            model: "openai-codex:gpt-5.5".into(),
            limits: AllowanceLimits {
                max_provider_calls: 7,
                protected_review_calls: 2,
            },
            reason: "Offline accounting test; no transport".into(),
            work_plan: None,
        })
        .unwrap();
    drop(
        ledger
            .reserve_provider_call(&AllowanceCall {
                investigation_id: id.clone(),
                expected_revision: 1,
                request_id: "reserved".into(),
                run_id: "offline-run".into(),
                work_id: "owned-context".into(),
                model: "openai-codex:gpt-5.5".into(),
                work: InvestigationWork::Context,
            })
            .unwrap(),
    );
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let study = &next
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .study;
    assert_eq!(study.investigation_id, id);
    assert!(!study.approved());
    let accounting = study.allowance.as_ref().unwrap();
    assert_eq!(accounting.committed_calls, 1);
    assert_eq!(accounting.unresolved_calls, 1);
    assert!(study.accounting_error.is_none());
    assert!(!next.has_running_work());
}

#[test]
fn changed_immutable_reference_blocks_restore_and_retains_original_checkpoint() {
    use kuzushi_core::capabilities::threat_model::{
        commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
    };
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let reference = commit_threat_model_revision(target.path(),&serde_json::json!({"version":"1","methodology":"stride","systemContext":"Owned inert source","dfd":{"nodes":[{"id":"source","name":"Owned text","type":"data-store","trustZone":"repository"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}),ThreatModelCommit {model_id:None,new_model:true,label:"Owned".into(),scope:ScopeRef::legacy_root(target.path(),&format!("sha256:{}","a".repeat(64))),methodology:"stride".into(),source:ThreatModelRevisionSource::Import,source_revision_id:None,run_id:None,activate:Some(false),actor:"test".into()}).unwrap().model_ref;
    let mut first = shell(target.path(), home.path());
    fill(&mut first, "Bound context");
    let config = first
        .router
        .campaign_mut()
        .batch_scan_config
        .as_mut()
        .unwrap();
    let mut value = serde_json::to_value(reference).unwrap();
    value["sha256"] = serde_json::json!(format!("sha256:{}", "f".repeat(64)));
    config.study.matrix.cases[1].threat_model_ref = value;
    first.checkpoint_study_choices();
    settle(&mut first);
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    assert!(matches!(
        next.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .draft_recovery,
        StudyDraftRecovery::Failed(_)
    ));
    assert!(!next.has_running_work());
    let (store, _) = next
        .runtime_state
        .study_checkpoints
        .binding
        .as_ref()
        .unwrap();
    assert_eq!(
        persistence::recover(store, &target.path().canonicalize().unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn partial_numeric_draft_survives_restart_without_changing_case_repetitions() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut first = shell(target.path(), home.path());
    fill(&mut first, "Numbers");
    key(&mut first, KeyCode::Char('p'));
    first.handle_batch_config_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    first.capture_batch_number_paste("12x");
    key(&mut first, KeyCode::Home);
    key(&mut first, KeyCode::Right);
    settle(&mut first);
    let expected = first
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .unwrap()
        .number_edit
        .clone();
    let mut next = shell(target.path(), home.path());
    key(&mut next, KeyCode::Enter);
    settle(&mut next);
    let config = next.router.campaign().batch_scan_config.as_ref().unwrap();
    assert_eq!(config.number_edit, expected);
    assert_eq!(config.study.matrix.planned_jobs(), 5);
    assert!(!config.study.approved());
    key(&mut next, KeyCode::Enter);
    assert!(next.batch_number_editor_open());
    key(&mut next, KeyCode::Esc);
    assert!(!next.batch_number_editor_open());
}

#[test]
fn an_over_limit_edit_cannot_borrow_an_older_saved_status() {
    let target = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut app = shell(target.path(), home.path());
    fill(&mut app, "Saved");
    key(&mut app, KeyCode::Char('n'));
    app.capture_context_case_name_paste(&"x".repeat(2049));
    settle(&mut app);
    assert!(!app.study_choices_checkpointed());
    assert!(app.study_choices_not_checkpointed());
    assert!(app.study_checkpoint_note().unwrap().contains("not saved"));
}

mod settings;
