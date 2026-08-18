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
    fn prompt_set_rejects_an_empty_override() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        let effects = app.handle_prompt_verb("set triage \"\"");

        assert!(effects.is_empty());
        assert!(!prompt_override_path(temp.path()).exists());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires a name and quoted value")));
    }

    #[test]
    fn prompt_write_invalidates_the_cached_override_hash() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.set_shell_view(ShellView::PromptsEditor);
        let path = prompt_override_path(temp.path());
        app.hydrate_all_view_data_for_test();
        assert!(matches!(
            app.workbench_cache()
                .borrow()
                .cached_prompt_override_hash(temp.path(), &path),
            ViewDataState::Ready(Ok(None))
        ));

        run_prompt_verb(&mut app, "set triage \"focus auth boundaries\"");

        assert!(matches!(
            app.workbench_cache()
                .borrow()
                .cached_prompt_override_hash(temp.path(), &path),
            ViewDataState::NotRequested
        ));
        app.hydrate_all_view_data_for_test();
        assert!(matches!(
            app.workbench_cache()
                .borrow()
                .cached_prompt_override_hash(temp.path(), &path),
            ViewDataState::Ready(Ok(Some(_)))
        ));
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
    fn prompt_mutate_rejects_an_empty_candidate() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        let effects = app.handle_prompt_verb("mutate triage \"\"");

        assert!(effects.is_empty());
        assert!(app.log_lines().iter().any(|line| line
            .body
            .contains("mutate requires a verb and quoted value")));
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
        let path = kuzushi_core::prompt_override_path(temp.path(), "sast", "triage");

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
    fn prompt_edit_does_not_create_empty_override_without_declared_template() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        run_prompt_verb(&mut app, "edit scan");

        let path = kuzushi_core::prompt_override_path(temp.path(), "sast", "scan");
        assert!(!path.exists());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("no editable built-in template")));
    }

    #[test]
    fn prompt_edit_without_declared_template_does_not_touch_unreadable_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = kuzushi_core::prompt_override_path(temp.path(), "sast", "scan");
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "edit scan");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("no editable built-in template")));
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
            .any(|line| line.body.contains("could not set override at")));
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
    fn prompt_show_reports_unreadable_undeclared_override_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = kuzushi_core::prompt_override_path(temp.path(), "sast", "scan");
        std::fs::create_dir_all(&path).unwrap();

        run_prompt_verb(&mut app, "show scan");

        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("could not read override at")));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains(".kuzushi/prompts/sast/scan.md")));
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

    #[cfg(unix)]
    #[test]
    fn prompt_effects_refuse_symlinked_override_directory() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_prompt = outside.path().join("triage.md");
        std::fs::write(&outside_prompt, "outside-prompt-secret").unwrap();
        let prompts = target.path().join(".kuzushi/prompts");
        std::fs::create_dir_all(&prompts).unwrap();
        symlink(outside.path(), prompts.join("sast")).unwrap();
        let mut app = prompt_test_app(target.path());

        for command in [
            "show triage",
            "list",
            "set triage \"replacement\"",
            "reset triage",
            "edit triage",
        ] {
            run_prompt_verb(&mut app, command);
        }

        assert_eq!(
            std::fs::read_to_string(&outside_prompt).unwrap(),
            "outside-prompt-secret"
        );
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("outside-prompt-secret")));
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.trim() == "- triage"));
    }

    #[cfg(unix)]
    #[test]
    fn tune_effects_refuse_symlinked_house_rules_directory() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_rules = outside.path().join("sast.md");
        std::fs::write(&outside_rules, "outside-house-rule-secret").unwrap();
        let state = target.path().join(".kuzushi");
        std::fs::create_dir_all(&state).unwrap();
        symlink(outside.path(), state.join("house-rules")).unwrap();
        let mut app = prompt_test_app(target.path());

        for command in ["show", "set \"replacement\"", "reset"] {
            run_tune_verb(&mut app, command);
        }

        assert_eq!(
            std::fs::read_to_string(&outside_rules).unwrap(),
            "outside-house-rule-secret"
        );
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("outside-house-rule-secret")));
    }

    #[test]
    fn prompt_document_opens_builtin_without_creating_override() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let prompt = app
            .prompt_spec_for_tool("agentic-sast:scan")
            .expect("agentic prompt descriptor");
        let path = kuzushi_core::prompt_override_path(temp.path(), "agentic-sast", "scan");

        app.open_prompt_document_effect(PromptDocumentOpen {
            prompts: vec![prompt],
            prompt_index: 0,
            origin: ShellView::PlanningPicker,
        });

        let document = app.router.prompts().document().expect("open document");
        assert_eq!(app.shell_view(), ShellView::PromptsEditor);
        assert_eq!(document.source, "built-in");
        assert!(document.text().contains("agentic SAST scanner"));
        assert!(!path.exists());

        app.reduce_key(key(KeyCode::Char('l')));
        assert_eq!(app.router.prompts().document().unwrap().cursor_col, 1);
    }

    #[test]
    fn prompt_document_vim_write_persists_and_returns_to_setup() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let prompt = app
            .prompt_spec_for_tool("agentic-sast:scan")
            .expect("agentic prompt descriptor");
        let path = kuzushi_core::prompt_override_path(temp.path(), "agentic-sast", "scan");
        app.open_prompt_document_effect(PromptDocumentOpen {
            prompts: vec![prompt],
            prompt_index: 0,
            origin: ShellView::PlanningPicker,
        });

        for code in [
            KeyCode::Char('i'),
            KeyCode::Char('X'),
            KeyCode::Esc,
            KeyCode::Char(':'),
            KeyCode::Char('w'),
            KeyCode::Char('q'),
        ] {
            let update = app.reduce_key(key(code));
            EffectRuntime::execute(&mut app, update.effects);
        }
        let update = app.reduce_key(key(KeyCode::Enter));
        EffectRuntime::execute(&mut app, update.effects);

        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert!(app.router.prompts().document().is_none());
        assert!(std::fs::read_to_string(path).unwrap().starts_with('X'));
    }

    #[test]
    fn prompt_document_refuses_empty_override_instead_of_claiming_it_is_active() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let prompt = app
            .prompt_spec_for_tool("agentic-sast:scan")
            .expect("agentic prompt descriptor");
        let path = kuzushi_core::prompt_override_path(temp.path(), "agentic-sast", "scan");
        app.open_prompt_document_effect(PromptDocumentOpen {
            prompts: vec![prompt],
            prompt_index: 0,
            origin: ShellView::PlanningPicker,
        });
        let document = app.router.prompts_mut().document_mut().unwrap();
        document.lines = vec![String::new()];
        document.trailing_newline = false;
        document.dirty = true;
        document.mode = PromptDocumentMode::Command;
        document.command = "wq".to_string();

        let update = app.reduce_key(key(KeyCode::Enter));

        assert!(update.effects.is_empty());
        assert!(!path.exists());
        assert_eq!(app.shell_view(), ShellView::PromptsEditor);
        assert!(app.router.prompts().document().unwrap().dirty);
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("empty files use the built-in default")));
    }

    #[test]
    fn dirty_prompt_document_requires_discard_confirmation() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let prompt = app
            .prompt_spec_for_tool("agentic-sast:scan")
            .expect("agentic prompt descriptor");
        app.open_prompt_document_effect(PromptDocumentOpen {
            prompts: vec![prompt],
            prompt_index: 0,
            origin: ShellView::PlanningPicker,
        });

        for code in [KeyCode::Char('i'), KeyCode::Char('X'), KeyCode::Esc] {
            app.reduce_key(key(code));
        }
        app.reduce_key(key(KeyCode::Esc));

        assert_eq!(
            app.router.prompts().document().unwrap().mode,
            PromptDocumentMode::ConfirmDiscard
        );
        app.reduce_key(key(KeyCode::Char('n')));
        assert_eq!(app.shell_view(), ShellView::PromptsEditor);
        app.reduce_key(key(KeyCode::Esc));
        app.reduce_key(key(KeyCode::Char('y')));
        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
    }

    #[test]
    fn planning_picker_plain_p_starts_a_command_instead_of_opening_a_prompt_editor() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.open_phase_picker(WorkflowPhase::Scan);
        app.engagement
            .planning_picker_mut()
            .selected_mut()
            .insert(PlanningTaskId::ScanAgenticSast);

        let agentic_index = app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .position(|row| row.id == PlanningTaskId::ScanAgenticSast)
            .unwrap();
        while app.engagement.planning_picker().cursor() < agentic_index {
            app.reduce_key(key(KeyCode::Down));
        }
        let update = app.reduce_key(key(KeyCode::Char('p')));
        EffectRuntime::execute(&mut app, update.effects);

        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        assert_eq!(
            app.engagement.planning_picker().focus(),
            PickerFocus::Prompt
        );
        assert_eq!(app.input(), "p");
    }

    #[test]
    fn planning_prompt_review_never_falls_back_to_another_selected_row() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.open_phase_picker(WorkflowPhase::Scan);
        let semgrep_index = app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .position(|row| row.id == PlanningTaskId::ScanSemgrep)
            .unwrap();
        let agentic_index = app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .position(|row| row.id == PlanningTaskId::ScanAgenticSast)
            .unwrap();
        let selected = app.engagement.planning_picker_mut().selected_mut();
        selected.clear();
        selected.extend([PlanningTaskId::ScanSemgrep, PlanningTaskId::ScanAgenticSast]);

        app.engagement
            .planning_picker_mut()
            .set_cursor(semgrep_index);
        assert!(!app.planning_prompt_review_available());
        assert!(app.review_planning_prompt().is_empty());

        app.engagement
            .planning_picker_mut()
            .set_cursor(agentic_index);
        assert!(app.planning_prompt_review_available());
    }

    #[test]
    fn prompts_surface_uses_all_declared_systems_hunt_roles() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        app.set_focused_module(Some("systems-hunt".to_string()));
        let prompts = app.focused_prompt_specs();

        assert_eq!(prompts.len(), 5);
        assert_eq!(prompts[0].verb, "invariants");
        assert_eq!(prompts[1].verb, "triggers");
        assert_eq!(prompts[2].verb, "hunt");
        assert_eq!(prompts[3].verb, "deep-semantic-cwe-select");
        assert_eq!(prompts[4].verb, "deep-semantic-hunt");
    }

    #[test]
    fn multi_role_prompt_review_cycles_in_declared_order_and_protects_edits() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let prompts = app.prompt_specs_for_tool("systems-hunt:systems-hunt");
        assert_eq!(prompts.len(), 3);
        app.open_prompt_document_effect(PromptDocumentOpen {
            prompts,
            prompt_index: 0,
            origin: ShellView::PlanningPicker,
        });

        let update = app.reduce_key(key(KeyCode::Char(']')));
        EffectRuntime::execute(&mut app, update.effects);
        assert_eq!(
            app.router.prompts().document().unwrap().role,
            "trigger synthesis"
        );

        for code in [KeyCode::Char('i'), KeyCode::Char('X'), KeyCode::Esc] {
            app.reduce_key(key(code));
        }
        let update = app.reduce_key(key(KeyCode::Char(']')));
        assert!(update.effects.is_empty());
        assert_eq!(
            app.router.prompts().document().unwrap().role,
            "trigger synthesis"
        );
    }
}
