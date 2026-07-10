#[cfg(test)]
mod tests {
    use super::super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use kuzushi_core::V2Config;

    fn prompt_test_app(target: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.to_path_buf()));
        app.set_focused_module(Some("sast".to_string()));
        app
    }

    fn prompt_override_path(target: &std::path::Path) -> std::path::PathBuf {
        kuzushi_core::prompt_override_path(target, "sast", "triage")
    }

    fn prompt_override_root(target: &std::path::Path) -> std::path::PathBuf {
        kuzushi_core::module_prompt_root(target, "sast")
    }

    fn house_rule_path(target: &std::path::Path) -> std::path::PathBuf {
        kuzushi_core::house_rule_path(target, "sast")
    }

    fn relative_prompt_override_path() -> String {
        kuzushi_core::relative_prompt_override_path("sast", "triage")
            .display()
            .to_string()
    }

    fn relative_prompt_override_root() -> String {
        kuzushi_core::relative_module_prompt_root("sast")
            .display()
            .to_string()
    }

    fn relative_house_rule_path() -> String {
        kuzushi_core::relative_house_rule_path("sast")
            .display()
            .to_string()
    }

    fn run_prompt_verb(app: &mut ShellApp, raw: &str) {
        let effects = app.handle_prompt_verb(raw);
        EffectRuntime::execute(app, effects);
    }

    fn run_tune_verb(app: &mut ShellApp, raw: &str) {
        let effects = app.handle_tune_verb(raw);
        EffectRuntime::execute(app, effects);
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn prompt_set_returns_write_effect_without_touching_disk() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());

        let effects = app.handle_prompt_verb("set triage \"focus on auth\"");

        assert!(!path.exists());
        match effects.as_slice() {
            [ShellEffect::WritePromptOverride(write)] => {
                assert_eq!(&write.path, &path);
                assert_eq!(write.value.as_str(), "focus on auth");
            }
            _ => panic!("expected a prompt write effect"),
        }
    }

    #[test]
    fn prompt_mutate_returns_record_effect_without_touching_disk() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = prompt_test_app(temp.path());

        let effects = app.handle_prompt_verb("mutate triage \"focus on authz paths\"");

        assert!(!kuzushi_core::prompt_mutations_path(&workspace).exists());
        match effects.as_slice() {
            [ShellEffect::RecordPromptMutation(record)] => {
                assert_eq!(record.target.as_deref(), Some(temp.path()));
                assert_eq!(record.module.as_str(), "sast");
                assert_eq!(record.verb.as_str(), "triage");
                assert_eq!(record.text.as_str(), "focus on authz paths");
            }
            _ => panic!("expected a prompt mutation record effect"),
        }
    }

    #[test]
    fn prompt_approve_returns_status_effect_without_touching_disk() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = prompt_test_app(temp.path());

        let effects = app.handle_prompt_verb("approve mutation-1 reviewed stack");

        assert!(!kuzushi_core::prompt_mutations_path(&workspace).exists());
        match effects.as_slice() {
            [ShellEffect::UpdatePromptMutationStatus(update)] => {
                assert_eq!(update.target.as_deref(), Some(temp.path()));
                assert_eq!(update.id.as_str(), "mutation-1");
                assert_eq!(update.status, kuzushi_core::PromptMutationStatus::Approved);
                assert_eq!(update.reason.as_deref(), Some("reviewed stack"));
            }
            _ => panic!("expected a prompt mutation status effect"),
        }
    }

    #[test]
    fn tune_set_returns_write_effect_without_touching_disk() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = house_rule_path(temp.path());

        let effects = app.handle_tune_verb("set \"focus on auth\"");

        assert!(!path.exists());
        match effects.as_slice() {
            [ShellEffect::WriteHouseRules(write)] => {
                assert_eq!(&write.path, &path);
                assert_eq!(write.value.as_str(), "focus on auth");
            }
            _ => panic!("expected a house-rules write effect"),
        }
    }

    #[test]
    fn prompts_hotkey_returns_effect_without_executing_it() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.set_shell_view(ShellView::PromptsEditor);
        app.set_input_mode(InputMode::Navigate);
        let path = kuzushi_core::prompt_override_path(temp.path(), "sast", "scan");

        let update = app.reduce_key(key(KeyCode::Char('s')));

        assert!(update.handled);
        assert!(!path.exists());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not read override at")));
        match update.effects.as_slice() {
            [ShellEffect::ShowPromptOverride(show)] => assert_eq!(&show.path, &path),
            _ => panic!("expected a prompt show effect"),
        }
    }

    #[test]
    fn tune_hotkey_returns_effect_without_executing_it() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.set_shell_view(ShellView::Tune);
        app.set_input_mode(InputMode::Navigate);
        let path = house_rule_path(temp.path());

        let update = app.reduce_key(key(KeyCode::Enter));

        assert!(update.handled);
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("no house rules set")));
        match update.effects.as_slice() {
            [ShellEffect::ShowHouseRules(show)] => assert_eq!(show.path.as_ref(), Some(&path)),
            _ => panic!("expected a house-rules show effect"),
        }
    }

    #[test]
    fn prompt_edit_seeds_override_file_and_logs_editor_command() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        run_prompt_verb(&mut app, "edit triage");

        let path = prompt_override_path(temp.path());
        assert!(path.exists());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("edit override at")));
    }

    #[test]
    fn prompt_edit_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "edit triage");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not edit unreadable override at")));
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("edit override at")));
    }

    #[test]
    fn prompt_set_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "set triage \"focus on auth\"");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not set unreadable override at")));
        assert!(path.is_dir());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("wrote ")));
    }

    #[test]
    fn prompt_mutate_records_pending_mutation_and_approval() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = prompt_test_app(temp.path());

        run_prompt_verb(&mut app, "mutate triage \"focus on authz paths\"");

        let mutations = kuzushi_core::load_prompt_mutations(&workspace).unwrap();
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].module_id, "sast");
        assert_eq!(mutations[0].verb, "triage");
        assert_eq!(mutations[0].text, "focus on authz paths");
        assert_eq!(
            mutations[0].status,
            kuzushi_core::PromptMutationStatus::Pending
        );
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("pending for sast:triage")));

        run_prompt_verb(
            &mut app,
            &format!("approve {} reviewed stack", mutations[0].id),
        );

        let approved = kuzushi_core::latest_prompt_mutation(&workspace, "sast", "triage")
            .unwrap()
            .unwrap();
        assert_eq!(
            approved.status,
            kuzushi_core::PromptMutationStatus::Approved
        );
        assert_eq!(approved.reason.as_deref(), Some("reviewed stack"));
        assert_eq!(
            std::fs::read_to_string(prompt_override_path(temp.path())).unwrap(),
            "focus on authz paths"
        );
    }

    #[test]
    fn prompt_list_reports_sorted_prompt_overrides_and_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        run_prompt_verb(&mut app, "list");
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("no override directory")));

        let dir = prompt_override_root(temp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("triage.md"), "triage").unwrap();
        std::fs::write(dir.join("verify.md"), "verify").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

        app.clear_log();
        run_prompt_verb(&mut app, "list");

        let messages = app
            .log_lines()
            .iter()
            .map(|line| line.body.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|line| line.contains("overrides in")));
        assert!(messages.contains(&"  - triage"));
        assert!(messages.contains(&"  - verify"));
        assert!(!messages.contains(&"  - notes"));
    }

    #[test]
    fn prompt_list_reports_unreadable_override_root() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let dir = prompt_override_root(temp.path());
        std::fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::fs::write(&dir, "not a directory").unwrap();

        run_prompt_verb(&mut app, "list");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not read override directory at")));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains(&relative_prompt_override_root())));
    }

    #[test]
    fn tune_show_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        run_tune_verb(&mut app, "show");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not read house rules at")));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains(&relative_house_rule_path())));
    }

    #[test]
    fn tune_reset_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        run_tune_verb(&mut app, "reset");

        assert!(app.log_lines().iter().any(|line| line
            .body
            .contains("could not reset unreadable house rules at")));
        assert!(rules.is_dir());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("removed ")));
    }

    #[test]
    fn tune_set_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        run_tune_verb(&mut app, "set \"focus on auth\"");

        assert!(app.log_lines().iter().any(|line| line
            .body
            .contains("could not set unreadable house rules at")));
        assert!(rules.is_dir());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("wrote ")));
    }

    #[test]
    fn prompt_show_reports_unreadable_override_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "show triage");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not read override at")));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains(&relative_prompt_override_path())));
    }

    #[test]
    fn prompt_diff_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "diff triage");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not diff unreadable override at")));
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("diff candidate:")));
    }

    #[test]
    fn prompt_reset_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "reset triage");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not reset unreadable override at")));
        assert!(path.is_dir());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("removed override")));
    }
}
