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
}
