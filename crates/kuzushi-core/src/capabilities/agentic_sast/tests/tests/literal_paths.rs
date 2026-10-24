use super::*;

#[test]
fn literal_paths_survive_agentic_output_normalization() {
    let root = tempdir().unwrap();
    for name in [
        " leading.rs",
        "trailing.rs ",
        "dir/a b.rs",
        "Case.rs",
        "case.rs",
        "a\\b.rs",
    ] {
        let raw = json!({"findings":[{"filePath":name,"title":"Owned source observation","severity":"info"}]});
        let findings = normalize_agentic_sast_findings(raw, root.path(), 1, false).unwrap();
        assert_eq!(findings[0].file_path, name);
    }
    let path = root.path().join(" literal 東京.rs ");
    let raw = json!({"findings":[{"filePath":path,"title":"Owned source observation","severity":"info"}]});
    assert_eq!(
        normalize_agentic_sast_findings(raw, root.path(), 1, false).unwrap()[0].file_path,
        " literal 東京.rs "
    );
}

#[test]
fn literal_paths_survive_source_sink_and_citation_location_fallbacks() {
    let root = tempdir().unwrap();
    for finding in [
        json!({"source":{"filePath":" literal.rs "}}),
        json!({"sink":{"file_path":" literal.rs "}}),
        json!({"citations":[{"filePath":" literal.rs "}]}),
    ] {
        let findings =
            normalize_agentic_sast_findings(json!({"findings":[finding]}), root.path(), 1, false)
                .unwrap();
        assert_eq!(findings[0].file_path, " literal.rs ");
    }
}

#[test]
fn literal_paths_are_not_merged_by_whitespace_case_or_native_separator_guesses() {
    let paths = [
        "src/a.rs",
        " src/a.rs",
        "src/a.rs ",
        "src/A.rs",
        "src\\a.rs",
    ];
    let findings = paths
        .iter()
        .map(|path| {
            Finding::new_tool(
                "agentic",
                "owned-rule",
                *path,
                1,
                None,
                Severity::Info,
                "Owned observation",
            )
        })
        .collect();
    let merged = merge_agentic_sast_findings(findings, Vec::new(), 10);
    #[cfg(unix)]
    assert_eq!(merged.len(), paths.len());
    #[cfg(windows)]
    assert_eq!(merged.len(), paths.len() - 1);
}
