#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn toggle_sast_task_blocks_enabled_tasks_and_allows_disabled_tasks() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let blocked = app.toggle_sast_task("semgrep").unwrap();
        assert!(blocked.contains("Blocked SAST task"));
        assert!(app.current_disabled_sast_tasks().contains("semgrep"));

        let allowed = app.toggle_sast_task("semgrep").unwrap();
        assert!(allowed.contains("Allowed SAST task"));
        assert!(!app.current_disabled_sast_tasks().contains("semgrep"));
    }

    #[test]
    fn toggle_sast_task_reports_unknown_ids_actionably() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let error = app.toggle_sast_task("made-up").unwrap_err().to_string();
        assert!(error.contains("unknown SAST task"));
    }
}
