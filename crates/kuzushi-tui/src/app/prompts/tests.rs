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

    #[test]
    fn prompt_edit_seeds_override_file_and_logs_editor_command() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("edit triage");

        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
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
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
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
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
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
    fn prompt_list_reports_sorted_prompt_overrides_and_missing_state() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());

        app.handle_prompt_verb("list");
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("no override directory")));

        let dir = temp.path().join(".kuzushi/prompts/sast");
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
        let dir = temp.path().join(".kuzushi/prompts/sast");
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
            .any(|line| line.body.contains(".kuzushi/prompts/sast")));
    }

    #[test]
    fn tune_show_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = temp.path().join(".kuzushi/house-rules/sast.md");
        std::fs::create_dir_all(&rules).unwrap();

        app.handle_tune_verb("show");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not read house rules at")));
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains(".kuzushi/house-rules/sast.md")));
    }

    #[test]
    fn tune_reset_reports_unreadable_house_rules_file() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let rules = temp.path().join(".kuzushi/house-rules/sast.md");
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
        let rules = temp.path().join(".kuzushi/house-rules/sast.md");
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
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
        std::fs::create_dir_all(&path).unwrap();

        app.handle_prompt_verb("show triage");

        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("could not read override at")));
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains(".kuzushi/prompts/sast/triage.md")));
    }

    #[test]
    fn prompt_diff_reports_unreadable_override_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = prompt_test_app(temp.path());
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
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
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
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
