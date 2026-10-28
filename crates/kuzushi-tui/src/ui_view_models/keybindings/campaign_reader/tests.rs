use super::*;
use crate::ui_view_models::keybindings::{bind, footer_keybindings};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::V2Config;
use serde_json::json;

fn reader(fixed: bool) -> ShellApp {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".kuzushi/v3/campaigns/owned");
    std::fs::create_dir_all(&path).unwrap();
    let kind = if fixed { "scope-study" } else { "campaign" };
    std::fs::write(
        path.join("plan.json"),
        serde_json::to_vec(&json!({
            "kind": kind, "workers": 1,
            "jobs": [{"jobId":"owned-job","tool":"sast:scan","input":{}}]
        }))
        .unwrap(),
    )
    .unwrap();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "owned",
    )
    .unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_shell_view(ShellView::Campaign);
    app.set_input_mode(InputMode::Navigate);
    let deck = app.router.campaign_mut();
    deck.campaigns = vec![snapshot];
    deck.detail = true;
    deck.job_detail = true;
    app
}

#[test]
fn enter_hint_matches_read_from_top_without_losing_the_job_or_draft() {
    let mut app = reader(true);
    app.set_input("held draft 😀\nsecond line");
    app.router.campaign_mut().read_scroll = 7;
    let before = app.router.campaign().selected_job().unwrap().job_id.clone();
    let bindings = footer_keybindings(&app);
    assert!(
        bindings.contains(&bind("Enter", "read from top")),
        "{bindings:?}"
    );
    assert!(!bindings.contains(&bind("Enter", "open jobs")));
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .handled
    );
    assert!(app.router.campaign().job_detail);
    assert_eq!(app.router.campaign().read_scroll, 0);
    assert_eq!(app.router.campaign().selected_job().unwrap().job_id, before);
    assert_eq!(app.input(), "held draft 😀\nsecond line");
}

#[test]
fn fixed_study_hints_omit_refused_edits_and_keep_valid_launch_and_review() {
    let app = reader(true);
    let bindings = footer_keybindings(&app);
    assert!(!bindings
        .iter()
        .any(|binding| matches!(binding.key.as_str(), "x" | "w")));
    assert!(bindings.contains(&bind("L", "launch")));
    assert!(bindings.contains(&bind("a", "plan and allowance")));
    assert!(bindings.contains(&bind("j/k", "jobs")));
    let exact = app.view_keybindings();
    for action in [
        ViewHotkeyAction::CampaignToggleExclude,
        ViewHotkeyAction::CampaignCycleWorkers,
    ] {
        assert!(exact.iter().any(|binding| binding.action == action));
    }
}

#[test]
fn legacy_reader_keeps_edit_hints_and_other_surfaces_keep_original_labels() {
    let mut app = reader(false);
    let bindings = footer_keybindings(&app);
    assert!(bindings.contains(&bind("x", "include/exclude")));
    assert!(bindings.contains(&bind("w", "workers")));
    for (view, mode, detail) in [
        (ShellView::Campaign, InputMode::Prompt, true),
        (ShellView::History, InputMode::Navigate, true),
    ] {
        app.set_shell_view(view);
        app.set_input_mode(mode);
        app.router.campaign_mut().job_detail = detail;
        assert_eq!(
            footer_label(
                &app,
                ViewHotkeyAction::CampaignOpenDetail,
                "open jobs".into()
            ),
            Some("open jobs".into())
        );
    }
}

#[test]
fn list_hints_follow_the_fixed_plan_and_name_the_actual_enter_action() {
    for fixed in [true, false] {
        for detail in [true, false] {
            let mut app = reader(fixed);
            app.router.campaign_mut().detail = detail;
            app.router.campaign_mut().job_detail = false;
            let bindings = footer_keybindings(&app);
            assert_eq!(bindings.contains(&bind("x", "include/exclude")), !fixed);
            assert_eq!(bindings.contains(&bind("w", "workers")), !fixed);
            let enter = if detail { "inspect job" } else { "open jobs" };
            assert!(bindings.contains(&bind("Enter", enter)), "{bindings:?}");
            assert!(app
                .view_keybindings()
                .iter()
                .any(|binding| { binding.action == ViewHotkeyAction::CampaignToggleExclude }));
        }
    }
}

#[test]
fn entering_a_list_job_preserves_the_selected_job_draft_and_fixed_work() {
    let mut app = reader(true);
    app.router.campaign_mut().job_detail = false;
    app.router.campaign_mut().read_scroll = 7;
    app.set_input("held list draft λ");
    assert!(footer_keybindings(&app).contains(&bind("Enter", "inspect job")));
    assert!(
        app.reduce_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .handled
    );
    let deck = app.router.campaign();
    assert!(deck.job_detail);
    assert_eq!(deck.selected_job().unwrap().job_id, "owned-job");
    assert_eq!(deck.read_scroll, 0);
    assert!(deck.excluded.is_empty());
    assert_eq!(app.input(), "held list draft λ");
    assert!(footer_keybindings(&app).contains(&bind("Enter", "read from top")));
}

#[test]
fn empty_lists_do_not_advertise_inspection_without_a_selection() {
    let mut app = reader(true);
    app.router.campaign_mut().campaigns[0].jobs.clear();
    assert!(!footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Enter"));
    app.router.campaign_mut().detail = false;
    app.router.campaign_mut().job_detail = false;
    assert!(footer_keybindings(&app).contains(&bind("Enter", "open jobs")));
    app.router.campaign_mut().campaigns.clear();
    assert!(!footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "Enter"));
}

#[test]
fn stop_hint_requires_an_active_dispatcher_without_an_existing_stop_request() {
    let mut app = reader(true);
    assert!(!footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "K"));
    app.router.campaign_mut().dispatcher_pid = Some(123);
    assert!(footer_keybindings(&app).contains(&bind("K", "stop dispatcher")));
    app.router.campaign_mut().dispatcher_stop_requested = true;
    assert!(!footer_keybindings(&app)
        .iter()
        .any(|binding| binding.key == "K"));
}

#[test]
fn launch_hint_tracks_the_shared_fixed_study_completion_check() {
    let mut app = reader(true);
    for state in ["planned", "running", "parked"] {
        app.router.campaign_mut().campaigns[0].jobs[0].state = state.into();
        assert!(
            footer_keybindings(&app).contains(&bind("L", "launch")),
            "{state}"
        );
    }
    for state in ["complete", "failed", "cancelled"] {
        app.router.campaign_mut().campaigns[0].jobs[0].state = state.into();
        assert!(
            !footer_keybindings(&app)
                .iter()
                .any(|binding| binding.key == "L"),
            "{state}"
        );
        assert!(app
            .view_keybindings()
            .iter()
            .any(|binding| binding.action == ViewHotkeyAction::CampaignLaunch));
    }
    app.router.campaign_mut().campaigns[0].kind = Some("campaign".into());
    assert!(footer_keybindings(&app).contains(&bind("L", "launch")));
}

#[test]
fn reader_actions_and_navigation_have_distinct_hints() {
    let app = reader(true);
    let hint = campaign_reader_action_hint(&app);
    assert!(hint.contains("R report") && hint.contains("a plan/allowance"));
    assert!(hint.contains("r refresh") && hint.contains("L launch"));
    assert!(!hint.contains("PgUp") && !hint.contains("q jobs"));
    let bindings = campaign_reader_footer(&app).unwrap();
    assert_eq!(bindings[0], bind("q", "jobs"));
    assert_eq!(bindings[1], bind("Enter", "read from top"));
    assert_eq!(bindings[2], bind("PgUp/PgDn", "scroll"));
    let cursor = bindings
        .iter()
        .position(|binding| binding.key == "j/k/↑/↓")
        .unwrap();
    for key in ["Ctrl+G", "Ctrl+C"] {
        assert!(
            bindings
                .iter()
                .position(|binding| binding.key == key)
                .unwrap()
                < cursor
        );
    }
    assert_eq!(
        app.view_keybindings()
            .into_iter()
            .find(|binding| binding.action == ViewHotkeyAction::CampaignBackToList)
            .unwrap()
            .label,
        "jobs"
    );
}

#[test]
fn stopping_hides_execution_hints_and_prompt_names_its_input_owner() {
    let mut app = reader(true);
    app.router.campaign_mut().dispatcher_pid = Some(123);
    assert!(campaign_reader_action_hint(&app).contains("K stop"));
    assert!(!campaign_reader_action_hint(&app).contains("L launch"));
    app.router.campaign_mut().dispatcher_stop_requested = true;
    let hint = campaign_reader_action_hint(&app);
    assert!(!hint.contains("K stop") && !hint.contains("L launch"));
    app.set_input_mode(InputMode::Prompt);
    app.set_input("retained draft λ");
    assert!(campaign_reader_action_hint(&app).contains("Esc Navigate"));
    assert!(campaign_reader_footer(&app).is_none());
    assert_eq!(app.input(), "retained draft λ");
}

#[test]
fn configured_composer_and_palette_keys_survive_reader_presentation() {
    use kuzushi_core::config::KeybindingOverrideConfig;
    let mut app = reader(true);
    let config = [
        KeybindingOverrideConfig {
            context: "composer".into(),
            action: "navigate_mode".into(),
            bindings: vec!["ctrl+n".into()],
        },
        KeybindingOverrideConfig {
            context: "global".into(),
            action: "command_palette".into(),
            bindings: vec!["ctrl+p".into()],
        },
    ];
    app.ui_mut()
        .replace_runtime_keymap(crate::app::RuntimeKeymap::from_config(&config))
        .unwrap();
    let footer = campaign_reader_footer(&app).unwrap();
    assert_eq!(footer[0], bind("q", "jobs"));
    assert!(footer.iter().any(|binding| binding.key == "ctrl+p"));
    assert!(!footer.iter().any(|binding| binding.key == "Ctrl+G"));
    app.set_input_mode(InputMode::Prompt);
    assert!(campaign_reader_action_hint(&app).starts_with("ctrl+n Navigate"));
    assert!(!campaign_reader_action_hint(&app).contains("Esc"));
    app.reduce_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL));
    assert_eq!(app.input_mode(), InputMode::Navigate);
}

#[test]
fn reader_does_not_advertise_an_unbound_composer_transition() {
    use kuzushi_core::config::KeybindingOverrideConfig;
    let mut app = reader(true);
    let config = [KeybindingOverrideConfig {
        context: "composer".into(),
        action: "navigate_mode".into(),
        bindings: vec![],
    }];
    app.ui_mut()
        .replace_runtime_keymap(crate::app::RuntimeKeymap::from_config(&config))
        .unwrap();
    app.set_input_mode(InputMode::Prompt);
    let hint = campaign_reader_action_hint(&app);
    assert!(hint.contains("Navigate unbound") && !hint.contains("Esc"));
}
