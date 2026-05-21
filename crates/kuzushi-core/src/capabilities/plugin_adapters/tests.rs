#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;
    use std::fs;

    #[test]
    fn list_tob_skills_reports_resolvable_and_unresolved_declared_skills() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("fp-check")).unwrap();
        fs::create_dir_all(temp.path().join("static-analysis")).unwrap();

        let report =
            list_tob_skills(json!({"pluginRoot": temp.path().display().to_string()})).unwrap();

        assert_eq!(report["ok"], json!(true));
        assert_completed_envelope(&report, "Resolvable ToB skill plugins");
        assert_eq!(report["data"]["resolvable"].as_array().unwrap().len(), 2);
        assert!(report["data"]["unresolved"]
            .as_array()
            .unwrap()
            .contains(&json!("variant-analysis")));
    }

    #[test]
    fn list_shinsa_frameworks_lists_skill_directories_and_frameworks() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("skills").join("annex-a")).unwrap();
        fs::write(temp.path().join("skills").join("README.md"), "not a skill").unwrap();

        let report =
            list_shinsa_frameworks(json!({"pluginRoot": temp.path().display().to_string()}))
                .unwrap();

        assert_eq!(report["ok"], json!(true));
        assert_completed_envelope(&report, "shinsa-plugin path:");
        assert_eq!(report["data"]["skills"], json!(["annex-a"]));
        assert_eq!(
            report["data"]["frameworks"],
            json!(["iso27001-annex-a", "nist-sp-800-53-rev5"])
        );
    }

    #[test]
    fn plugin_list_commands_return_actionable_json_when_root_is_missing() {
        let tob = list_tob_skills(json!({})).unwrap();
        assert_eq!(tob["ok"], json!(false));
        assert_failed_envelope(&tob, "tob:skills requires");
        assert!(tob["output"]
            .as_str()
            .unwrap()
            .contains("tob:skills requires"));

        let shinsa = list_shinsa_frameworks(json!({})).unwrap();
        assert_eq!(shinsa["ok"], json!(false));
        assert_failed_envelope(&shinsa, "shinsa:frameworks requires");
        assert!(shinsa["output"]
            .as_str()
            .unwrap()
            .contains("shinsa:frameworks requires"));
    }

    fn assert_completed_envelope(value: &serde_json::Value, summary_prefix: &str) {
        assert_eq!(value.get("status"), Some(&json!("completed")));
        assert!(value
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        assert!(value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty));
    }

    fn assert_failed_envelope(value: &serde_json::Value, summary_prefix: &str) {
        assert_eq!(value.get("status"), Some(&json!("failed")));
        assert!(value
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|summary| summary.starts_with(summary_prefix)));
        assert!(value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| !errors.is_empty()));
    }
}
