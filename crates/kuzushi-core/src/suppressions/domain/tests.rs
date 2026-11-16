use super::*;
use crate::findings::{Finding, FindingEvidence, Severity};
use crate::workspace::ProgramScope;

fn finding(fingerprint: &str, tool: &str, rule_id: &str, severity: Severity) -> Finding {
    Finding {
        fingerprint: fingerprint.to_string(),
        tool: tool.to_string(),
        rule_id: rule_id.to_string(),
        severity,
        file_path: "src/app.rs".to_string(),
        ..Finding::default()
    }
}

fn rule(id: &str, origin: SuppressionOrigin, predicate: SuppressionPredicate) -> SuppressionRule {
    SuppressionRule {
        id: id.to_string(),
        predicate,
        reason: SuppressionReason::FalsePositive,
        statement: "because".to_string(),
        actor: "tester".to_string(),
        created_at_unix: 100,
        expires_at_unix: None,
        origin,
    }
}

fn ref_predicate(fingerprint: &str) -> SuppressionPredicate {
    SuppressionPredicate {
        finding_id: Some(FindingRef(fingerprint.to_string())),
        ..SuppressionPredicate::empty()
    }
}

#[test]
fn severity_below_excludes_unknown_and_threshold() {
    let low = finding("fp-low", "semgrep", "r1", Severity::Low);
    let unknown = finding("fp-unk", "semgrep", "r1", Severity::Unknown);
    let medium = finding("fp-med", "semgrep", "r1", Severity::Medium);
    let mut predicate = SuppressionPredicate::empty();
    predicate.severity_below = Some(Severity::Medium);
    let rules = vec![rule("sup-sev", SuppressionOrigin::File, predicate)];

    let report = evaluate_suppressions(&[low, unknown, medium], &rules, None, 1000);
    // low < medium suppressed; unknown never; medium not below itself.
    assert_eq!(report.active_count, 1);
    assert!(matches!(report.states[0].state, SuppressionState::Active(_)));
    assert!(matches!(report.states[1].state, SuppressionState::None));
    assert!(matches!(report.states[2].state, SuppressionState::None));
    assert!(report.findings_remain_visible);
}

#[test]
fn first_match_wins_prefers_more_specific_origin() {
    let f = finding("fp1", "semgrep", "r1", Severity::High);
    let comment = SuppressionRule {
        reason: SuppressionReason::UsedInTests,
        ..rule("sup-comment", SuppressionOrigin::InSourceComment, ref_predicate("fp1"))
    };
    let scope = SuppressionRule {
        reason: SuppressionReason::OutOfScope,
        ..rule("sup-scope", SuppressionOrigin::ScopeToml, ref_predicate("fp1"))
    };
    // Pass in scope-first ordering; specificity sort must still pick comment.
    let report = evaluate_suppressions(&[f], &[scope, comment], None, 1000);
    match &report.states[0].state {
        SuppressionState::Active(m) => {
            assert_eq!(m.rule_id, "sup-comment");
            assert_eq!(m.reason, SuppressionReason::UsedInTests);
        }
        other => panic!("expected active, got {other:?}"),
    }
}

#[test]
fn expired_rule_reopens_and_is_reported() {
    let f = finding("fp1", "semgrep", "r1", Severity::High);
    let expired = SuppressionRule {
        expires_at_unix: Some(500),
        ..rule("sup-old", SuppressionOrigin::File, ref_predicate("fp1"))
    };
    let report = evaluate_suppressions(&[f], &[expired], None, 1000);
    assert_eq!(report.active_count, 0);
    match &report.states[0].state {
        SuppressionState::Expired { rule_id, expired_at_unix } => {
            assert_eq!(rule_id, "sup-old");
            assert_eq!(*expired_at_unix, 500);
        }
        other => panic!("expected expired, got {other:?}"),
    }
    assert_eq!(report.reopened_by_expiry.len(), 1);
    assert_eq!(report.expired_rules, vec!["sup-old".to_string()]);
}

#[test]
fn live_rule_wins_over_lapsed_rule_for_same_finding() {
    let f = finding("fp1", "semgrep", "r1", Severity::High);
    let expired = SuppressionRule {
        expires_at_unix: Some(500),
        ..rule("sup-old", SuppressionOrigin::File, ref_predicate("fp1"))
    };
    let live = rule("sup-live", SuppressionOrigin::File, ref_predicate("fp1"));
    let report = evaluate_suppressions(&[f], &[expired, live], None, 1000);
    assert!(matches!(report.states[0].state, SuppressionState::Active(_)));
    assert_eq!(report.active_count, 1);
    assert!(report.reopened_by_expiry.is_empty());
}

#[test]
fn path_glob_and_module_and_ref_matchers() {
    let mut in_tests = finding("fp1", "taint-iris:hunt", "r1", Severity::High);
    in_tests.file_path = "tests/thing_test.rs".to_string();
    let mut predicate = SuppressionPredicate::empty();
    predicate.path_glob = Some(
        globset::Glob::new("tests/**")
            .unwrap()
            .compile_matcher(),
    );
    predicate.module = Some("taint-iris".to_string());
    let rules = vec![rule("sup-path", SuppressionOrigin::File, predicate)];
    let report = evaluate_suppressions(&[in_tests], &rules, None, 1000);
    assert!(matches!(report.states[0].state, SuppressionState::Active(_)));

    // A finding outside tests/ or a different module must not match.
    let elsewhere = finding("fp2", "semgrep", "r1", Severity::High);
    let report2 = evaluate_suppressions(&[elsewhere], &rules, None, 1000);
    assert!(matches!(report2.states[0].state, SuppressionState::None));
}

#[test]
fn scope_status_only_matches_host_bearing_findings() {
    let scope = ProgramScope::parse(
        r#"
        [in_scope]
        hosts = ["*.example.com"]
        "#,
    )
    .unwrap();
    let mut http = finding("fp-http", "burp", "r1", Severity::High);
    http.evidence.push(FindingEvidence {
        kind: "http-request".to_string(),
        request_blob: Some("GET / HTTP/1.1\r\nHost: admin.evil.test\r\n\r\n".to_string()),
        ..FindingEvidence::default()
    });
    let code = finding("fp-code", "semgrep", "r1", Severity::High);

    let mut predicate = SuppressionPredicate::empty();
    predicate.scope_status = Some(crate::workspace::ScopeVerdict::OutOfScope);
    let rules = [rule("sup-scope", SuppressionOrigin::ScopeToml, predicate)];

    let report = evaluate_suppressions(&[http, code], &[rules[0].clone()], Some(&scope), 1000);
    // http finding host is out-of-scope (allow-list present, unmatched) → suppressed.
    assert!(matches!(report.states[0].state, SuppressionState::Active(_)));
    // code finding has no host → predicate does not match.
    assert!(matches!(report.states[1].state, SuppressionState::None));
}

#[test]
fn reason_and_origin_round_trip_tokens() {
    assert_eq!(SuppressionReason::parse("false-positive"), Some(SuppressionReason::FalsePositive));
    assert_eq!(SuppressionReason::parse("out_of_scope"), Some(SuppressionReason::OutOfScope));
    assert_eq!(SuppressionReason::parse("bogus"), None);
    assert_eq!(SuppressionReason::FalsePositive.as_str(), "false-positive");
    assert_eq!(SuppressionOrigin::InSourceComment.specificity_rank(), 0);
    assert!(
        SuppressionOrigin::InSourceComment.specificity_rank()
            < SuppressionOrigin::ScopeToml.specificity_rank()
    );
}

fn http_capture(fingerprint: &str, url: &str, blob: &str) -> Finding {
    let mut finding = finding(fingerprint, "burp-xml", "http-evidence", Severity::High);
    finding.file_path = url.to_string();
    finding.evidence.push(FindingEvidence {
        kind: "http-request".to_string(),
        file_path: url.to_string(),
        request_blob: Some(blob.to_string()),
        ..FindingEvidence::default()
    });
    finding
}

fn scope_rule_state(scope: &ProgramScope, findings: &[Finding]) -> Vec<SuppressionState> {
    let mut predicate = SuppressionPredicate::empty();
    predicate.scope_status = Some(crate::workspace::ScopeVerdict::OutOfScope);
    let rules = [rule("sup-scope", SuppressionOrigin::ScopeToml, predicate)];
    evaluate_suppressions(findings, &rules, Some(scope), 1000)
        .states
        .into_iter()
        .map(|entry| entry.state)
        .collect()
}

fn example_com_allow_list() -> ProgramScope {
    ProgramScope::parse(
        r#"
        [in_scope]
        hosts = ["*.example.com"]
        "#,
    )
    .unwrap()
}

/// The scope rule compiled from `scope.toml` suppresses an out-of-scope host,
/// and a suppressed finding is dropped from the `--fail-on` gate. A URL the
/// request merely carries — in its query string, or in a `Referer` that
/// precedes `Host` — is not the host it was sent to, so it must not decide
/// that verdict.
#[test]
fn a_url_the_request_carries_does_not_put_an_in_scope_capture_out_of_scope() {
    let scope = example_com_allow_list();
    let redirect = http_capture(
        "fp-redirect",
        "https://api.example.com/redirect?next=https://partner.out-of-scope.test/",
        "GET /redirect?next=https://partner.out-of-scope.test/ HTTP/1.1\r\n\
         Host: api.example.com\r\n\r\n",
    );
    let referred = http_capture(
        "fp-referred",
        "https://api.example.com/login",
        "POST /login HTTP/1.1\r\n\
         Referer: https://cdn.thirdparty.test/sso\r\n\
         Host: api.example.com\r\n\r\n",
    );
    let webhook = http_capture(
        "fp-webhook",
        "https://api.example.com/hooks",
        "POST /hooks HTTP/1.1\r\n\
         Host: api.example.com\r\n\r\n\
         {\"callback\":\"https://out-of-scope.test/cb\"}",
    );

    let states = scope_rule_state(&scope, &[redirect, referred, webhook]);

    for state in &states {
        assert!(
            matches!(state, SuppressionState::None),
            "in-scope capture was suppressed as out of scope: {state:?}"
        );
    }
}

/// A capture genuinely outside the program is still annotated, from whichever
/// of the two places states its host.
#[test]
fn an_out_of_scope_capture_is_still_suppressed_by_the_scope_rule() {
    let scope = example_com_allow_list();
    let by_url = http_capture(
        "fp-url",
        "https://admin.evil.test/panel",
        "GET /panel HTTP/1.1\r\nHost: admin.evil.test\r\n\r\n",
    );
    let mut by_blob = by_url.clone();
    by_blob.fingerprint = "fp-blob".to_string();
    by_blob.evidence[0].file_path = String::new();
    let mut by_absolute_form = by_url.clone();
    by_absolute_form.fingerprint = "fp-absolute".to_string();
    by_absolute_form.evidence[0].file_path = String::new();
    by_absolute_form.evidence[0].request_blob =
        Some("GET https://admin.evil.test/panel HTTP/1.1\r\n\r\n".to_string());

    let states = scope_rule_state(&scope, &[by_url, by_blob, by_absolute_form]);

    for state in &states {
        assert!(
            matches!(state, SuppressionState::Active(_)),
            "out-of-scope capture was not annotated: {state:?}"
        );
    }
}

/// The importers gate on the URL the capture recorded and store it on the
/// evidence, so the sweep reads that same URL rather than re-deriving a host
/// from the raw message and reaching a different answer about one finding.
#[test]
fn the_recorded_capture_url_decides_scope_before_the_raw_request() {
    let scope = example_com_allow_list();
    let disagreeing = http_capture(
        "fp-recorded",
        "https://api.example.com/login",
        "POST /login HTTP/1.1\r\nHost: admin.evil.test\r\n\r\n",
    );

    let states = scope_rule_state(&scope, &[disagreeing]);

    assert!(matches!(states[0], SuppressionState::None), "{:?}", states[0]);
}
