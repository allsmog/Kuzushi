#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    fn prompt_test_app(target: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(target.to_path_buf());
        app.focused_module = Some("sast".to_string());
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

    #[test]
    fn prompt_edit_seeds_override_file_and_logs_editor_command() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("edit triage");

        let path = prompt_override_path(temp.path());
        assert!(path.exists());
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("edit override at")));
    }

    #[test]
    fn prompt_edit_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("edit triage");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not edit unreadable override at")));
        assert!(!app
            .log
            .iter()
            .any(|line| line.body.contains("edit override at")));
    }

    #[test]
    fn prompt_set_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("set triage \"focus on auth\"");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not set unreadable override at")));
        assert!(path.is_dir());
        assert!(!app.log.iter().any(|line| line.body.contains("wrote ")));
    }

    #[test]
    fn prompt_mutate_records_pending_mutation_and_approval() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("mutate triage \"focus on authz paths\"");

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
            .log
            .iter()
            .any(|line| line.body.contains("pending for sast:triage")));

        app.handle_prompt_verb(&format!("approve {} reviewed stack", mutations[0].id));

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

        app.handle_prompt_verb("list");
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("no override directory")));

        let dir = prompt_override_root(temp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("triage.md"), "triage").unwrap();
        std::fs::write(dir.join("verify.md"), "verify").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

        app.log.clear();
        app.handle_prompt_verb("list");

        let messages = app
            .log
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

        app.handle_prompt_verb("list");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not read override directory at")));
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains(&relative_prompt_override_root())));
    }

    #[test]
    fn tune_show_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        app.handle_tune_verb("show");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not read house rules at")));
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains(&relative_house_rule_path())));
    }

    #[test]
    fn tune_reset_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        app.handle_tune_verb("reset");

        assert!(app.log.iter().any(|line| line
            .body
            .contains("could not reset unreadable house rules at")));
        assert!(rules.is_dir());
        assert!(!app.log.iter().any(|line| line.body.contains("removed ")));
    }

    #[test]
    fn tune_set_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = house_rule_path(temp.path());
        std::fs::create_dir_all(&rules).unwrap();

        app.handle_tune_verb("set \"focus on auth\"");

        assert!(app.log.iter().any(|line| line
            .body
            .contains("could not set unreadable house rules at")));
        assert!(rules.is_dir());
        assert!(!app.log.iter().any(|line| line.body.contains("wrote ")));
    }

    #[test]
    fn prompt_show_reports_unreadable_override_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("show triage");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not read override at")));
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains(&relative_prompt_override_path())));
    }

    #[test]
    fn prompt_diff_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("diff triage");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not diff unreadable override at")));
        assert!(!app
            .log
            .iter()
            .any(|line| line.body.contains("diff candidate:")));
    }

    #[test]
    fn prompt_reset_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = prompt_override_path(temp.path());
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("reset triage");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not reset unreadable override at")));
        assert!(path.is_dir());
        assert!(!app
            .log
            .iter()
            .any(|line| line.body.contains("removed override")));
    }
}
