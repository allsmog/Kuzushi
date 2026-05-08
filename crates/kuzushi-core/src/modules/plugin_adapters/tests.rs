#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn list_tob_skills_reports_resolvable_and_unresolved_declared_skills() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("fp-check")).unwrap();
        fs::create_dir_all(temp.path().join("static-analysis")).unwrap();

        let report =
            list_tob_skills(json!({"pluginRoot": temp.path().display().to_string()})).unwrap();

        assert_eq!(report["ok"], json!(true));
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
        assert!(tob["output"]
            .as_str()
            .unwrap()
            .contains("tob:skills requires"));

        let shinsa = list_shinsa_frameworks(json!({})).unwrap();
        assert_eq!(shinsa["ok"], json!(false));
        assert!(shinsa["output"]
            .as_str()
            .unwrap()
            .contains("shinsa:frameworks requires"));
    }
}
