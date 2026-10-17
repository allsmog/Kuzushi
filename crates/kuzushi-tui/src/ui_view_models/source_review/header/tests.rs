use super::*;
use serde_json::json;

#[test]
fn recorded_sha_supports_both_git_hash_formats_and_never_invents_a_clean_state() {
    for (count, dirty, suffix) in [
        (40, json!(true), "dirty"),
        (64, json!(false), "clean"),
        (40, Value::Null, "unknown"),
    ] {
        let capture =
            json!({"reviewedSource":{"sourceGit":{"sha":"a".repeat(count),"dirty":dirty}}});
        assert_eq!(
            captured_identity(Some(&capture)),
            format!("Captured SHA aaaaaaaaaaaa · {suffix}")
        );
    }
}

#[test]
fn missing_git_uses_recorded_content_without_promoting_it_to_a_commit() {
    let capture = json!({"reviewedSource":{"treeHash":"b".repeat(64)}});
    assert_eq!(
        captured_identity(Some(&capture)),
        "Content bbbbbbbbbbbb · Git unknown"
    );
    assert_eq!(captured_identity(None), "Source not captured");
    assert_eq!(
        captured_identity(Some(&json!({}))),
        "Source identity unavailable"
    );
}

#[test]
fn malformed_identities_cannot_enter_a_terminal_header() {
    let capture = json!({"reviewedSource":{"sourceGit":{"sha":"\u{001b}[31mwrong","dirty":false},"treeHash":"x".repeat(64)}});
    assert_eq!(
        captured_identity(Some(&capture)),
        "Source identity unavailable"
    );
}
