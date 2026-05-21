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

    #[test]
    fn legacy_carlini_task_aliases_resolve_to_offense_review() {
        for alias in [
            "carlini",
            "threat-hunt",
            "carlini-threat-hunt",
            "carlini-threat-hunt:run",
            "offense-review:threat-hunt",
        ] {
            let task = resolve_sast_task(alias).unwrap();
            assert_eq!(task.id, "offense-review");
            assert_eq!(task.scan_task, "offense-review");
        }

        assert!(!valid_sast_task_ids().contains(&"carlini-threat-hunt"));
    }

    #[test]
    fn cargo_audit_task_aliases_resolve_to_native_scanner() {
        for alias in ["cargo-audit", "cargo audit", "cargo-audit:scan"] {
            let task = resolve_sast_task(alias).unwrap();
            assert_eq!(task.id, "cargo-audit");
            assert_eq!(task.scan_task, "cargo-audit");
            assert!(task.default_enabled);
        }

        assert!(valid_sast_task_ids().contains(&"cargo-audit"));
    }

    #[test]
    fn license_scan_task_aliases_resolve_to_native_scanner() {
        for alias in ["license-scan", "license", "licenses", "license-scan:scan"] {
            let task = resolve_sast_task(alias).unwrap();
            assert_eq!(task.id, "license-scan");
            assert_eq!(task.scan_task, "license-scan");
            assert!(!task.default_enabled);
        }

        assert!(valid_sast_task_ids().contains(&"license-scan"));
    }

    #[test]
    fn systems_hunt_task_is_deferred_exact_opt_in() {
        let task = resolve_sast_task("systems-hunt").unwrap();

        assert_eq!(task.id, "systems-hunt");
        assert_eq!(task.scan_task, "systems-hunt");
        assert!(!task.default_enabled);
        assert!(task.notes.contains("deferred exact opt-in"));
    }
}
