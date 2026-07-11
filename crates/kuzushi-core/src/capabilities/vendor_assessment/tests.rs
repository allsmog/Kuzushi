#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;

    #[test]
    fn scope_sets_persists_and_clears_vendor_assessment_scope() {
        let temp = tempfile::tempdir().unwrap();

        let updated = scope(
            temp.path(),
            ScopeUpdate {
                vendor_name: Some("Acme".to_string()),
                product_name: Some("Acme AI".to_string()),
                profile: Some("enterprise-ai".to_string()),
                ..ScopeUpdate::default()
            },
            false,
        )
        .unwrap();
        assert_completed_envelope(&updated, "Vendor assessment scope");
        assert_eq!(
            updated.pointer("/data/scope/vendorName"),
            Some(&json!("Acme"))
        );
        assert!(temp
            .path()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());

        let cleared = scope(temp.path(), ScopeUpdate::default(), true).unwrap();
        assert_completed_envelope(&cleared, "Vendor assessment draft scope cleared.");
        assert_eq!(cleared.pointer("/data/cleared"), Some(&json!(true)));
        assert_eq!(cleared.pointer("/data/scope/vendorName"), Some(&json!("")));
        assert_eq!(cleared.pointer("/data/scope/documents"), Some(&json!([])));
    }

    #[test]
    fn prompts_and_assessment_report_artifacts_are_top_level() {
        let temp = tempfile::tempdir().unwrap();
        let update = ScopeUpdate {
            vendor_name: Some("Acme".to_string()),
            product_name: Some("Acme AI".to_string()),
            profile: Some("enterprise-ai".to_string()),
            ..ScopeUpdate::default()
        };

        let prompts = prompts(temp.path(), update.clone(), Some("run-prompts".to_string()))
            .expect("prompt bundle");
        assert_completed_envelope(&prompts, "Prompt bundle written");
        assert!(prompts
            .pointer("/artifacts/0/path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(
                |path| path.ends_with(".kuzushi/vendor-assessment/runs/run-prompts/prompts")
            ));

        let report = assess(temp.path(), update, None, None, || {
            Ok("openai:gpt-test".to_string())
        })
        .expect("fallback assessment");
        assert_completed_envelope(&report, "Vendor assessment complete");
        assert!(report
            .get("artifacts")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|artifacts| artifacts.len() == 4));
        assert!(report
            .pointer("/artifacts/0/path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| path.ends_with("report.md")));
    }

    #[test]
    fn prompt_run_id_cannot_escape_vendor_state() {
        let temp = tempfile::tempdir().unwrap();

        let error = prompts(
            temp.path(),
            ScopeUpdate::default(),
            Some("../../outside".to_string()),
        )
        .unwrap_err();

        assert!(error.to_string().contains("runId"));
        assert!(!temp.path().join("outside").exists());
    }

    #[cfg(unix)]
    #[test]
    fn scope_read_and_write_do_not_follow_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "outside-secret").unwrap();
        let state_dir = workspace.path().join(".kuzushi/vendor-assessment");
        std::fs::create_dir_all(&state_dir).unwrap();
        symlink(outside.path(), state_dir.join("scope.json")).unwrap();

        assert!(scope(workspace.path(), ScopeUpdate::default(), false).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "outside-secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn assessment_preflights_all_outputs_before_scope_or_model_work() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let run_root = workspace
            .path()
            .join(".kuzushi/vendor-assessment/runs/preflight");
        std::fs::create_dir_all(&run_root).unwrap();
        std::fs::write(outside.path(), "outside sentinel").unwrap();
        symlink(outside.path(), run_root.join("report.md")).unwrap();

        let error = assess(
            workspace.path(),
            ScopeUpdate {
                vendor_name: Some("must-not-persist".to_string()),
                ..ScopeUpdate::default()
            },
            Some("preflight".to_string()),
            None,
            || Ok("openai:gpt-test".to_string()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("symlink"));
        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "outside sentinel"
        );
        assert!(!workspace
            .path()
            .join(".kuzushi/vendor-assessment/scope.json")
            .exists());
    }

    fn assert_completed_envelope(value: &serde_json::Value, summary_prefix: &str) {
        assert_eq!(value.get("ok"), Some(&json!(true)));
        assert_eq!(value.get("status"), Some(&json!("completed")));
        assert!(value
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        assert!(value
            .get("warnings")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty));
        assert!(value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty));
    }
}
