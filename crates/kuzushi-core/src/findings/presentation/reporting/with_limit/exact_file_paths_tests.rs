use super::*;

fn finding(path: &str) -> Finding {
    Finding::new_tool(
        "owned",
        "rule",
        path,
        1,
        None,
        Severity::High,
        "observation",
    )
}

#[test]
fn exact_paths_match_any_path_without_substring_or_case_expansion() {
    let filter = FindingListFilter::from_tool_input(&serde_json::json!({
        "filePaths": ["src/a b.rs", "src/a,b.rs"]
    }))
    .unwrap();
    for path in ["src/a b.rs", "./src/a,b.rs", r"src\a b.rs"] {
        assert!(
            filter.matches_with_review_decision(&finding(path), None),
            "{path}"
        );
    }
    for path in ["src/a b.rs.bak", "other/src/a b.rs", "src/A B.rs"] {
        assert!(
            !filter.matches_with_review_decision(&finding(path), None),
            "{path}"
        );
    }
}

#[test]
fn exact_paths_combine_with_existing_filters_and_aliases() {
    let filter = FindingListFilter::from_tool_input(&serde_json::json!({
        "file_paths": ["src/a.rs", "tests/a.rs"], "filePath": "src/", "severity": ["high"]
    }))
    .unwrap();
    assert!(filter.matches_with_review_decision(&finding("src/a.rs"), None));
    assert!(!filter.matches_with_review_decision(&finding("tests/a.rs"), None));
    let mut low = finding("src/a.rs");
    low.severity = Severity::Low;
    assert!(!filter.matches_with_review_decision(&low, None));
}

#[test]
fn exact_path_expression_and_prepared_input_share_semantics() {
    let paths = serde_json::json!(["src/a b.rs", "src/a,b.rs"]);
    let expression = FindingListFilter::from_filter_expression(&format!("files:{paths}")).unwrap();
    let input =
        FindingListFilter::from_tool_input(&serde_json::json!({"filePaths":paths})).unwrap();
    assert_eq!(expression, input);
}

#[test]
fn empty_exact_paths_keep_existing_file_filter_behavior() {
    let filter =
        FindingListFilter::from_tool_input(&serde_json::json!({"filePath":"a.rs"})).unwrap();
    assert!(filter.matches_with_review_decision(&finding("src/a.rs.backup"), None));
}

#[test]
fn shared_preparation_preserves_literal_array_items() {
    let registry = crate::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let input = registry
        .prepare_tool_input(
            "findings:list",
            serde_json::json!({
                "file_paths":["src/a,b.rs", "src/a b.rs"]
            }),
            None,
        )
        .unwrap();
    let filter = FindingListFilter::from_tool_input(&input).unwrap();
    assert_eq!(filter.file_paths, ["src/a,b.rs", "src/a b.rs"]);
}

#[test]
fn tool_filter_expression_preserves_case_and_literal_suffixes() {
    let expression = r#"files:["src/Scope#L7.tf","src/a  b.rs:7","src/`tag`.rs"] severity:high"#;
    let registry = crate::ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_tool_input(
            "findings:list",
            serde_json::json!({"filter":expression}),
            None,
        )
        .unwrap();
    let input_filter = FindingListFilter::from_tool_input(&prepared).unwrap();
    let expression_filter = FindingListFilter::from_filter_expression(expression).unwrap();
    assert_eq!(input_filter, expression_filter);
    for path in ["src/Scope#L7.tf", "src/a  b.rs:7", "src/`tag`.rs"] {
        assert!(input_filter.matches_with_review_decision(&finding(path), None));
    }
    assert!(!input_filter.matches_with_review_decision(&finding("src/scope#l7.tf"), None));
}

#[test]
fn tool_filter_expression_keeps_case_insensitive_legacy_predicates() {
    let filter = FindingListFilter::from_tool_input(
        &serde_json::json!({"filter":"SEVERITY:HIGH FILE:SRC/ NAME:OBSERVATION"}),
    )
    .unwrap();
    assert!(filter.matches_with_review_decision(&finding("src/Main.rs"), None));
    assert!(FindingListFilter::from_tool_input(&serde_json::json!({"filter":42})).is_err());
}
