use super::*;
use serde_json::json;

#[test]
fn literal_paths_preserve_whitespace_citation_suffixes_and_delimiters() {
    let paths = [
        "app/a  b.rs:123",
        "app/a.rs#L7",
        "app/`code`.rs",
        " app/edge.rs ",
        "app/a,b.rs",
    ];
    for path in paths {
        for value in [
            json!({"path":path}),
            json!({"affectedFiles":[path]}),
            json!({"affectedFiles":[{"filePath":path}]}),
            json!({"evidenceRefs":[{"locator":{"path":path}}]}),
        ] {
            let evidence = security_evidence(&value);
            assert_eq!(evidence.files, [path]);
            assert_eq!(evidence.references, [path]);
        }
    }
}

#[test]
fn citations_keep_display_locations_but_query_only_the_file() {
    for (reference, path) in [
        ("app/a.rs:7:3", "app/a.rs"),
        ("app/a.rs:7-9", "app/a.rs"),
        ("app/a.rs#L7-L9", "app/a.rs"),
        ("`app/a  b.rs:7`", "app/a  b.rs"),
    ] {
        let evidence = security_evidence(&json!({"evidenceRefs":[{"source":reference}]}));
        assert_eq!(evidence.files, [path]);
        assert_eq!(evidence.references, [reference.trim_matches('`')]);
    }
}

#[test]
fn literal_and_citation_fields_with_identical_text_keep_both_file_meanings() {
    let evidence = security_evidence(&json!({"path":"app/a.rs:7", "evidence":"app/a.rs:7"}));
    assert_eq!(evidence.references, ["app/a.rs:7"]);
    assert_eq!(evidence.files, ["app/a.rs", "app/a.rs:7"]);
}

#[test]
fn prose_is_not_a_file_and_invalid_fragments_are_not_line_numbers() {
    let evidence = security_evidence(
        &json!({"evidenceRefs":["Look in app/a.rs for the handler", "app/a.rs#Literal", "app/a.rs:not-a-line"]}),
    );
    assert_eq!(evidence.files, ["app/a.rs#Literal", "app/a.rs:not-a-line"]);
}
