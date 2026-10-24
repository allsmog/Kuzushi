use super::*;
use crate::ui_view_models::{footer_keybindings, quit_confirm_model, work_liveness, WorkLiveness};

struct OwnedStudy {
    root: tempfile::TempDir,
    app: ShellApp,
    owner: serde_json::Value,
}

impl OwnedStudy {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let owner = serde_json::json!({"schemaVersion":1,"sessionId":uuid::Uuid::new_v4().to_string(),
            "campaignId":"owned-study","pid":child.id()});
        let directory =
            kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "owned-study");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("dispatcher-control.json"), owner.to_string()).unwrap();
        let mut app = ShellApp::new(Default::default(), None);
        app.set_target(Some(root.path().into()));
        app.runtime_state
            .hold_dispatcher(child, root.path().into(), "owned-study".into());
        app.set_shell_view(ShellView::Workbench);
        app.set_input_mode(InputMode::Prompt);
        app.set_input("retained study draft λ");
        app.set_cursor(7);
        Self { root, app, owner }
    }

    fn stop_path(&self) -> PathBuf {
        self.directory().join("dispatcher-stop.json")
    }

    fn directory(&self) -> PathBuf {
        kuzushi_core::capabilities::campaign::campaign_dir(self.root.path(), "owned-study")
    }

    fn cancel(&mut self, letter: char) {
        let update = self
            .app
            .reduce_key(KeyEvent::new(KeyCode::Char(letter), KeyModifiers::CONTROL));
        assert!(matches!(
            update.effects.as_slice(),
            [ShellEffect::CancelActiveJobs]
        ));
        self.app.cancel_active_jobs_effect();
    }
}

impl Drop for OwnedStudy {
    fn drop(&mut self) {
        if let Some(mut child) = self.app.runtime_state.take_dispatcher_child() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn owned_study_is_live_without_treating_a_recorded_pid_as_owned_work() {
    let study = OwnedStudy::new();
    assert!(study.app.has_running_work());
    assert_eq!(work_liveness(&study.app), WorkLiveness::Live);
    let bindings = footer_keybindings(&study.app);
    assert!(bindings
        .iter()
        .any(|binding| binding.key == "Ctrl+C" && binding.label == "request abort"));
    let mut unowned = ShellApp::new(Default::default(), None);
    unowned.router.campaign_mut().dispatcher_pid = Some(std::process::id());
    assert!(!unowned.has_running_work());
    assert_eq!(work_liveness(&unowned), WorkLiveness::Idle);
}

#[test]
fn quit_chords_stop_the_owned_study_and_wait_without_losing_the_draft() {
    for letter in ['c', 'd'] {
        let mut study = OwnedStudy::new();
        study.cancel(letter);
        let token = std::fs::read(study.stop_path()).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&token).unwrap(),
            study.owner
        );
        assert!(study.app.has_running_work() && !study.app.should_quit());
        assert_ne!(study.app.shell_view(), ShellView::QuitConfirm);
        assert!(study.app.router.campaign().dispatcher_stop_requested);
        let update = study
            .app
            .reduce_key(KeyEvent::new(KeyCode::Char(letter), KeyModifiers::CONTROL));
        assert!(update.handled && update.effects.is_empty());
        assert_eq!(std::fs::read(study.stop_path()).unwrap(), token);
        assert!(footer_keybindings(&study.app)
            .iter()
            .any(|binding| binding.key == "Ctrl+C" && binding.label == "wait cleanup"));
        assert_eq!(
            (study.app.input(), study.app.cursor()),
            ("retained study draft λ", 7)
        );
    }
}

#[test]
fn cancel_after_target_switch_uses_the_original_owned_study() {
    let mut study = OwnedStudy::new();
    let other = tempfile::tempdir().unwrap();
    study.app.set_target(Some(other.path().into()));
    study.app.router.campaign_mut().dispatcher_pid = Some(u32::MAX);
    study.cancel('c');
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(study.stop_path()).unwrap())
            .unwrap(),
        study.owner
    );
    assert!(!other
        .path()
        .join(".kuzushi/v3/campaigns/owned-study/dispatcher-stop.json")
        .exists());
    assert!(study.app.has_running_work() && !study.app.should_quit());
}

#[test]
fn failed_stop_stays_active_and_can_be_requested_again_after_repair() {
    let mut study = OwnedStudy::new();
    let control = study.directory().join("dispatcher-control.json");
    std::fs::write(&control, "{owned malformed control}").unwrap();
    study.cancel('c');
    assert!(study.app.has_running_work() && !study.stop_path().exists());
    assert!(!study.app.router.campaign().dispatcher_stop_requested);
    assert!(study
        .app
        .advisory()
        .notice
        .as_ref()
        .unwrap()
        .message
        .contains("Stop unavailable"));
    std::fs::write(control, study.owner.to_string()).unwrap();
    study.cancel('d');
    assert!(study.stop_path().is_file() && !study.app.should_quit());
}

#[test]
fn exit_disclosure_does_not_call_an_owned_study_idle() {
    let study = OwnedStudy::new();
    let model = quit_confirm_model(&study.app);
    assert!(!model.warning_body.contains("no active work"));
    assert!(model.warning_body.contains("may continue"));
    assert!(model.status.cost.contains("unknown"));
    let rows = model
        .sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rows.contains("owned-study"));
    assert!(rows.contains("Cost: unknown (owned study)"));
    assert!(rows.contains(&study.root.path().display().to_string()));
}

fn local_scan(app: &mut ShellApp, abort_requested: bool) {
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("local-scan".into()),
        target: PathBuf::from("."),
        stage: "owned adapter fixture".into(),
        findings_count: 0,
        running: true,
        abort_requested,
        error: None,
    }));
}

#[test]
fn pending_local_cancel_does_not_hide_an_uncanceled_owned_study() {
    let mut study = OwnedStudy::new();
    local_scan(&mut study.app, true);
    study.cancel('c');
    assert!(study.stop_path().is_file());
    assert!(study.app.abort_request_pending());
}

#[test]
fn pending_study_stop_does_not_hide_new_uncanceled_local_work() {
    let mut study = OwnedStudy::new();
    study.cancel('c');
    let token = std::fs::read(study.stop_path()).unwrap();
    local_scan(&mut study.app, false);
    assert!(!study.app.abort_request_pending());
    study.cancel('d');
    assert!(study.app.scan().unwrap().abort_requested);
    assert_eq!(std::fs::read(study.stop_path()).unwrap(), token);
}

#[test]
fn unset_budget_exit_does_not_turn_unknown_session_cost_into_zero() {
    let mut app = ShellApp::new(Default::default(), None);
    app.record_cost_report(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE);
    let model = quit_confirm_model(&app);
    assert!(
        model.status.cost.contains("not recorded"),
        "{}",
        model.status.cost
    );
}

#[test]
fn deck_stop_and_global_cancel_share_the_same_pending_state() {
    let mut study = OwnedStudy::new();
    study
        .app
        .apply_campaign_hotkey(ViewHotkeyAction::CampaignKill);
    assert!(study.app.runtime_state.owned_dispatcher_stop_requested());
    assert!(study.stop_path().exists());
    let update = study
        .app
        .reduce_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(update.handled && update.effects.is_empty());
    assert!(!study.app.should_quit());
}
