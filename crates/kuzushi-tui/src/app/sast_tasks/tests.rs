#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn toggle_sast_task_blocks_enabled_tasks_and_allows_disabled_tasks() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let blocked =
            app.reduce_sast_task_command(SastTaskCommand::Toggle(Some("semgrep".to_string())));
        assert!(matches!(
            blocked.first(),
            Some(ShellEffect::ApplySastTaskOptions(_))
        ));
        assert!(!app.current_disabled_sast_tasks().contains("semgrep"));
        EffectRuntime::execute(&mut app, blocked);
        assert!(app.current_disabled_sast_tasks().contains("semgrep"));

        let allowed =
            app.reduce_sast_task_command(SastTaskCommand::Toggle(Some("semgrep".to_string())));
        assert!(matches!(
            allowed.first(),
            Some(ShellEffect::ApplySastTaskOptions(_))
        ));
        EffectRuntime::execute(&mut app, allowed);
        assert!(!app.current_disabled_sast_tasks().contains("semgrep"));
    }

    #[test]
    fn toggle_sast_task_reports_unknown_ids_actionably() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let effects =
            app.reduce_sast_task_command(SastTaskCommand::Toggle(Some("made-up".to_string())));
        match effects.first() {
            Some(ShellEffect::FinalizeSastTaskCommand(finalize)) => match &finalize.outcome {
                SastTaskCommandOutcome::Error(error) => {
                    assert!(error.contains("unknown SAST task"));
                }
                SastTaskCommandOutcome::Applied(message) => {
                    panic!("expected error, got applied message {message}");
                }
            },
            _ => panic!("expected finalize SAST task command effect"),
        }
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
    fn govulncheck_task_aliases_resolve_to_native_scanner() {
        for alias in ["govulncheck", "go vuln", "go-vuln", "govulncheck:scan"] {
            let task = resolve_sast_task(alias).unwrap();
            assert_eq!(task.id, "govulncheck");
            assert_eq!(task.scan_task, "govulncheck");
            assert!(!task.default_enabled);
        }

        assert!(valid_sast_task_ids().contains(&"govulncheck"));
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
