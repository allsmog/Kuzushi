use super::*;

fn recorded_pair(left: &str, right: &str) -> (tempfile::TempDir, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open(root.path().join("findings.db")).unwrap();
    for (name, path) in [("alpha", left), ("beta", right)] {
        store
            .with_run_lifecycle(name, root.path(), || {
                let finding = Finding::new_tool(
                    name,
                    name,
                    path,
                    1,
                    None,
                    Severity::Info,
                    "Owned literal metadata fixture",
                );
                store.insert_finding(name, &finding)?;
                Ok(((), 1usize))
            })
            .unwrap();
    }
    (root, store)
}

#[test]
fn distinct_literal_paths_never_form_candidates_or_valid_duplicate_groups() {
    for (left, right) in [
        ("Case.rs", "case.rs"),
        (" leading.rs", "leading.rs"),
        ("trailing.rs ", "trailing.rs"),
        ("a\\b.rs", "a/b.rs"),
        ("./a.rs", "a.rs"),
    ] {
        let (_root, store) = recorded_pair(left, right);
        let findings = store.list_all_findings().unwrap();
        assert_eq!(findings.len(), 2);
        assert!(
            dedupe_candidates(&store, 200).unwrap().is_empty(),
            "{left:?} and {right:?}"
        );
        let group = one_group(&findings);
        let value = serde_json::json!({"groups":[{
            "canonical_fingerprint":group[0].canonical_fingerprint,
            "duplicate_fingerprints":group[0].duplicate_fingerprints,
            "root_cause_summary":"Synthetic model proposal; different recorded files",
            "confidence":0.95}]});
        let result =
            super::super::validate::validate_dedupe_output(value, 1, &fingerprint_index(&findings))
                .unwrap();
        assert!(
            result.groups.is_empty(),
            "model output must not erase literal path differences"
        );
    }
}
