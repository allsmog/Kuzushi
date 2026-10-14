use super::*;

fn choices(target: &Path) -> ReportPreferences {
    ReportPreferences {
        schema_version: 1, target: target.to_owned(), format: WorkspaceExportFormat::Json,
        completeness: WorkspaceExportCompleteness::Open, provenance_details: true,
        destinations: ["json", "jsonl", "sarif", "csv", "markdown-bundle", "vuln-findings"]
            .map(|format| (format.to_owned(), format!("reports/owned-{format}"))).into_iter().collect(),
    }
}

#[test]
fn saved_report_choices_round_trip_without_exporting_or_altering_source() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("owned.rs"), "// Owned inert source\n").unwrap();
    let preferences = choices(&std::fs::canonicalize(target.path()).unwrap());
    assert_eq!(load_report_preferences(home.path(), target.path()).unwrap(), None);
    save_report_preferences(home.path(), &preferences).unwrap();
    assert_eq!(load_report_preferences(home.path(), target.path()).unwrap(), Some(preferences));
    assert!(!target.path().join("reports").exists());
    assert_eq!(std::fs::read_to_string(target.path().join("owned.rs")).unwrap(), "// Owned inert source\n");
}

#[test]
fn repositories_are_isolated_and_foreign_saved_target_is_rejected() {
    let home = tempfile::tempdir().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let target = std::fs::canonicalize(first.path()).unwrap();
    let mut preferences = choices(&target);
    let path = save_report_preferences(home.path(), &preferences).unwrap();
    assert!(load_report_preferences(home.path(), second.path()).unwrap().is_none());
    preferences.target = second.path().to_owned();
    std::fs::write(path, serde_json::to_vec(&preferences).unwrap()).unwrap();
    assert!(load_report_preferences(home.path(), first.path()).unwrap_err().to_string().contains("different target"));
}

#[test]
fn malformed_oversized_and_unknown_version_files_are_honest_errors() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let preferences = choices(&std::fs::canonicalize(target.path()).unwrap());
    let path = save_report_preferences(home.path(), &preferences).unwrap();
    std::fs::write(&path, "{broken").unwrap();
    assert!(load_report_preferences(home.path(), target.path()).is_err());
    std::fs::write(&path, vec![b'x'; MAX_BYTES + 1]).unwrap();
    assert!(load_report_preferences(home.path(), target.path()).is_err());
    let mut future = preferences;
    future.schema_version = 2;
    std::fs::write(path, serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(load_report_preferences(home.path(), target.path()).is_err());
}

#[test]
fn invalid_destination_or_alias_keys_cannot_replace_valid_saved_choices() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let original = choices(&std::fs::canonicalize(target.path()).unwrap());
    let path = save_report_preferences(home.path(), &original).unwrap();
    let before = std::fs::read(&path).unwrap();
    for invalid in ["", "reports/line\nbreak", "reports/\0bad"] {
        let mut preferences = original.clone();
        preferences.destinations.insert("json".into(), invalid.into());
        assert!(save_report_preferences(home.path(), &preferences).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let mut alias = original;
    alias.destinations.remove("jsonl");
    alias.destinations.insert("ndjson".into(), "alias".into());
    assert!(save_report_preferences(home.path(), &alias).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn symlinked_operator_store_is_rejected() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".kuzushi/v3")).unwrap();
    std::os::unix::fs::symlink(outside.path(), home.path().join(".kuzushi/v3/report-choices")).unwrap();
    let preferences = choices(&std::fs::canonicalize(target.path()).unwrap());
    assert!(save_report_preferences(home.path(), &preferences).is_err());
    assert!(load_report_preferences(home.path(), target.path()).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}
