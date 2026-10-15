use super::*;

#[test]
fn oversized_saved_catalog_cannot_be_treated_as_absent_for_merge() {
    let root = tempfile::tempdir().unwrap();
    let path = taint_iris_next_target_catalog_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::File::create(&path)
        .unwrap()
        .set_len(TARGET_CATALOG_MAX_BYTES as u64 + 1)
        .unwrap();
    assert!(load_target_catalog_for_merge(root.path()).is_err());
    assert_eq!(
        std::fs::metadata(path).unwrap().len(),
        TARGET_CATALOG_MAX_BYTES as u64 + 1
    );
}

#[test]
fn output_larger_than_its_reader_cap_preserves_the_previous_catalog() {
    let root = tempfile::tempdir().unwrap();
    let path = taint_iris_next_target_catalog_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "Owned prior metadata").unwrap();
    let entry = TaintIrisNextRankedCatalogEntry {
        cwe: "CWE-20".to_string(),
        name: "Owned metadata".to_string(),
        taint_class: "owned".to_string(),
        languages: vec!["any".to_string()],
        source_signals: Vec::new(),
        sink_signals: vec!["a".repeat(TARGET_CATALOG_MAX_BYTES)],
        sanitizer_signals: Vec::new(),
        structural_queries: Vec::new(),
        regex_markers: Vec::new(),
        score: 0,
        reasons: Vec::new(),
    };
    assert!(persist_target_catalog(root.path(), &[entry]).is_err());
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "Owned prior metadata"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_saved_catalog_is_an_error_during_merge() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let path = taint_iris_next_target_catalog_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let outside = other.path().join("metadata.json");
    std::fs::write(&outside, "Owned outside metadata").unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    assert!(load_target_catalog_for_merge(root.path()).is_err());
    assert_eq!(
        std::fs::read_to_string(outside).unwrap(),
        "Owned outside metadata"
    );
}
