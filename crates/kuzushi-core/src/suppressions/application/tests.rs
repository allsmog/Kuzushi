use super::compile_scope_rule::compile_scope_rule;
use super::reconcile_suppression_events::reconcile_suppression_events;
use crate::findings::{Finding, FindingStore, Severity};
use crate::suppressions::domain::{
    evaluate_suppressions, FindingRef, SuppressionOrigin, SuppressionPredicate, SuppressionReason,
    SuppressionRule,
};
use crate::workspace::ProgramScope;

fn file_rule(id: &str, fingerprint: &str, expires_at_unix: Option<u64>) -> SuppressionRule {
    SuppressionRule {
        id: id.to_string(),
        predicate: SuppressionPredicate {
            finding_id: Some(FindingRef(fingerprint.to_string())),
            ..SuppressionPredicate::empty()
        },
        reason: SuppressionReason::FalsePositive,
        statement: "sanitizer applied upstream".to_string(),
        actor: "tester".to_string(),
        created_at_unix: 100,
        expires_at_unix,
        origin: SuppressionOrigin::File,
    }
}

fn seeded_store() -> (FindingStore, Finding) {
    let store = FindingStore::open_in_memory().unwrap();
    store
        .record_run_started("run-sup", std::path::Path::new("/tmp"), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "semgrep",
        "rust.sqli.tainted-query",
        "src/db.rs",
        20,
        Some(20),
        Severity::High,
        "tainted query, CWE-89",
    );
    store.insert_finding("run-sup", &finding).unwrap();
    let stored = store.list_findings(10).unwrap().into_iter().next().unwrap();
    (store, stored)
}

#[test]
fn reconcile_suppresses_then_is_idempotent() {
    let (store, finding) = seeded_store();
    let rules = vec![file_rule("sup-1", &finding.fingerprint, None)];
    let report = evaluate_suppressions(&[finding.clone()], &rules, None, 1000);

    let summary = reconcile_suppression_events(&store, &report, "tester").unwrap();
    assert_eq!(summary.added, 1);

    // Hydration makes the suppressed flag live.
    let reloaded = store.list_findings(10).unwrap();
    assert!(reloaded[0].suppressed, "finding should hydrate as suppressed");

    // Second reconcile over unchanged state appends nothing.
    let report2 = evaluate_suppressions(&reloaded, &rules, None, 1000);
    let summary2 = reconcile_suppression_events(&store, &report2, "tester").unwrap();
    assert!(summary2.is_noop(), "reconcile must be idempotent: {summary2:?}");
}

#[test]
fn finding_stays_visible_and_lists_by_status_suppressed() {
    let (store, finding) = seeded_store();
    let rules = vec![file_rule("sup-1", &finding.fingerprint, None)];
    let report = evaluate_suppressions(&[finding], &rules, None, 1000);
    reconcile_suppression_events(&store, &report, "tester").unwrap();

    // Default listing still includes the suppressed finding (annotate, not hide).
    let listed = store.list_findings(10).unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].suppressed);
}

#[test]
fn expired_rule_reopens_previously_suppressed_finding() {
    let (store, finding) = seeded_store();
    let live = vec![file_rule("sup-1", &finding.fingerprint, None)];
    let report = evaluate_suppressions(&[finding.clone()], &live, None, 1000);
    reconcile_suppression_events(&store, &report, "tester").unwrap();
    assert!(store.list_findings(10).unwrap()[0].suppressed);

    // Rule now has a past expiry → evaluation is Expired → reconcile reopens.
    let lapsed = vec![file_rule("sup-1", &finding.fingerprint, Some(500))];
    let reloaded = store.list_findings(10).unwrap();
    let report2 = evaluate_suppressions(&reloaded, &lapsed, None, 1000);
    let summary = reconcile_suppression_events(&store, &report2, "system:sweep").unwrap();
    assert_eq!(summary.expired, 1);
    assert!(!store.list_findings(10).unwrap()[0].suppressed, "expiry must reopen");
}

#[test]
fn compile_scope_rule_skips_empty_scope() {
    assert!(compile_scope_rule(&ProgramScope::default()).is_none());
    let scope = ProgramScope::parse(
        r#"
        [in_scope]
        hosts = ["*.example.com"]
        "#,
    )
    .unwrap();
    let rule = compile_scope_rule(&scope).unwrap();
    assert_eq!(rule.reason, SuppressionReason::OutOfScope);
    assert_eq!(rule.origin, SuppressionOrigin::ScopeToml);
}

#[test]
fn whitebox_records_compile_to_rules() {
    use crate::proof::suppressions::{WhiteboxSuppressionRecord, WhiteboxSuppressionScope};
    let record = WhiteboxSuppressionRecord {
        id: "wb1".to_string(),
        scope: WhiteboxSuppressionScope {
            finding_fingerprint: Some("fp-abc".to_string()),
            rule_id: "rust.sqli".to_string(),
            file_path: "src/db.rs".to_string(),
            start_line: 10,
            end_line: 12,
            snippet_hash: "hash".to_string(),
        },
        evidence: vec![],
        reason: "false-positive".to_string(),
        author: "tester".to_string(),
        created_at_unix: 100,
        expires_at_unix: 0,
        metadata: serde_json::Value::Null,
    };
    let rules = super::compile_whitebox_rules::compile_whitebox_rules(&[record]);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].origin, SuppressionOrigin::Whitebox);
    assert_eq!(rules[0].reason, SuppressionReason::FalsePositive);
    assert_eq!(rules[0].expires_at_unix, None, "zero expiry means never");
    assert_eq!(
        rules[0].predicate.finding_id.as_ref().map(|r| r.0.as_str()),
        Some("fp-abc")
    );
}
