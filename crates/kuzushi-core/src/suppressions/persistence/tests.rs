use super::*;
use crate::suppressions::domain::{
    FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason, SuppressionRule,
};
use crate::workspace::WorkspaceTarget;

fn workspace() -> (tempfile::TempDir, WorkspaceTarget) {
    let dir = tempfile::tempdir().unwrap();
    let target = WorkspaceTarget::new(dir.path()).unwrap();
    (dir, target)
}

fn sample_rule(id: &str) -> SuppressionRule {
    SuppressionRule {
        id: id.to_string(),
        predicate: SuppressionPredicate {
            finding_id: Some(FindingRef("fi_abc".to_string())),
            ..SuppressionPredicate::empty()
        },
        reason: SuppressionReason::FalsePositive,
        statement: "sanitizer applied upstream".to_string(),
        actor: "shayaun".to_string(),
        created_at_unix: 1_700_000_000,
        expires_at_unix: Some(1_800_000_000),
        origin: SuppressionOrigin::File,
    }
}

#[test]
fn absent_file_is_empty() {
    let (_dir, workspace) = workspace();
    assert!(load_suppression_rules(&workspace).unwrap().is_empty());
}

#[test]
fn round_trips_a_rule() {
    let (_dir, workspace) = workspace();
    save_suppression_rules(&workspace, &[sample_rule("sup-1")]).unwrap();
    let loaded = load_suppression_rules(&workspace).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, "sup-1");
    assert_eq!(loaded[0].reason, SuppressionReason::FalsePositive);
    assert_eq!(loaded[0].expires_at_unix, Some(1_800_000_000));
    assert_eq!(
        loaded[0]
            .predicate
            .finding_id
            .as_ref()
            .map(|r| r.0.as_str()),
        Some("fi_abc")
    );
}

#[cfg(unix)]
#[test]
fn suppression_writer_rejects_a_symlinked_artifact() {
    use std::os::unix::fs::symlink;

    let (_dir, workspace) = workspace();
    let mut outside = tempfile::NamedTempFile::new().expect("outside");
    std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
    workspace.ensure_state_dir().expect("state dir");
    symlink(outside.path(), workspace.suppressions_path()).expect("symlink artifact");

    let error = save_suppression_rules(&workspace, &[sample_rule("sup-1")])
        .expect_err("symlink must be rejected");

    assert!(error.to_string().contains("symlink"));
    assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
}

#[cfg(unix)]
#[test]
fn suppression_reader_rejects_an_outside_symlink_without_disclosing_content() {
    use std::os::unix::fs::symlink;

    let (_dir, workspace) = workspace();
    let outside = tempfile::NamedTempFile::new().expect("outside");
    std::fs::write(outside.path(), "OUTSIDE_SUPPRESSIONS_TOKEN").unwrap();
    workspace.ensure_state_dir().unwrap();
    symlink(outside.path(), workspace.suppressions_path()).unwrap();

    let error = load_suppression_rules(&workspace).unwrap_err().to_string();

    assert!(error.contains("symlink"), "{error}");
    assert!(!error.contains("OUTSIDE_SUPPRESSIONS_TOKEN"));
}

#[test]
fn upsert_replaces_same_id_and_remove_deletes() {
    let (_dir, workspace) = workspace();
    upsert_suppression_rule(&workspace, sample_rule("sup-1")).unwrap();
    let mut updated = sample_rule("sup-1");
    updated.statement = "revised".to_string();
    upsert_suppression_rule(&workspace, updated).unwrap();
    let loaded = load_suppression_rules(&workspace).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].statement, "revised");

    assert!(remove_suppression_rule(&workspace, "sup-1").unwrap());
    assert!(load_suppression_rules(&workspace).unwrap().is_empty());
    assert!(!remove_suppression_rule(&workspace, "sup-1").unwrap());
}

#[test]
fn unknown_key_is_rejected() {
    let (_dir, workspace) = workspace();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(
        workspace.suppressions_path(),
        r#"
version = 1
[[rule]]
reason = "false-positive"
statement = "x"
actor = "a"
created_at_unix = 1
typo_key = "boom"
[rule.match]
rule_id = "r1"
"#,
    )
    .unwrap();
    assert!(load_suppression_rules(&workspace).is_err());
}

#[test]
fn missing_statement_is_rejected() {
    let (_dir, workspace) = workspace();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(
        workspace.suppressions_path(),
        r#"
version = 1
[[rule]]
reason = "false-positive"
statement = ""
actor = "a"
created_at_unix = 1
[rule.match]
rule_id = "r1"
"#,
    )
    .unwrap();
    let err = load_suppression_rules(&workspace).unwrap_err().to_string();
    assert!(err.contains("statement"), "got: {err}");
}

#[test]
fn empty_match_is_rejected() {
    let (_dir, workspace) = workspace();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(
        workspace.suppressions_path(),
        r#"
version = 1
[[rule]]
reason = "false-positive"
statement = "x"
actor = "a"
created_at_unix = 1
[rule.match]
"#,
    )
    .unwrap();
    assert!(load_suppression_rules(&workspace).is_err());
}

#[test]
fn both_expiry_forms_is_rejected() {
    let (_dir, workspace) = workspace();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(
        workspace.suppressions_path(),
        r#"
version = 1
[[rule]]
reason = "false-positive"
statement = "x"
actor = "a"
created_at_unix = 1
expires_at_unix = 100
expires = "2026-12-31"
[rule.match]
rule_id = "r1"
"#,
    )
    .unwrap();
    let err = load_suppression_rules(&workspace).unwrap_err().to_string();
    assert!(err.contains("expires"), "got: {err}");
}

#[test]
fn expires_alias_is_converted() {
    let (_dir, workspace) = workspace();
    workspace.ensure_state_dir().unwrap();
    std::fs::write(
        workspace.suppressions_path(),
        r#"
version = 1
[[rule]]
reason = "acceptable-risk"
statement = "x"
actor = "a"
created_at_unix = 1
expires = "1970-01-02"
[rule.match]
rule_id = "r1"
"#,
    )
    .unwrap();
    let loaded = load_suppression_rules(&workspace).unwrap();
    assert_eq!(loaded[0].expires_at_unix, Some(86_400));
}

#[test]
fn derived_id_is_deterministic() {
    let predicate = SuppressionPredicate {
        rule_id: Some("r1".to_string()),
        ..SuppressionPredicate::empty()
    };
    let a = derive_rule_id(&predicate, SuppressionReason::FalsePositive);
    let b = derive_rule_id(&predicate, SuppressionReason::FalsePositive);
    assert_eq!(a, b);
    assert!(a.starts_with("sup-"));
}
