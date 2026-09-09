use super::*;
use serde_json::json;

fn review(value: Value) -> TriageOutcome {
    let outcome = AgentLoopOutcome {
        text: String::new(),
        structured: Some(value),
        steps_used: 4,
        truncated: false,
        cost_usd: 0.02,
        cost_usd_exact: false,
        transcript: Vec::new(),
    };
    let analysis = parse_vuln_analysis(&outcome);
    build_triage_outcome(&analysis, &outcome)
}

#[test]
fn unresolved_reachability_is_not_refuted_at_high_confidence() {
    let result = review(json!({
        "triggerable": null,
        "confidence": 0.95,
        "rationale": "Unsafe copy exists; the external calling contract is unavailable.",
        "refute_reason": "implausible_trigger"
    }));
    assert_eq!(result.verdict, TriageVerdict::NeedsReview);
    assert_eq!(result.refute_reason, None);
    assert_eq!(result.confidence, 0.95);
    assert!(result.rationale.contains("external calling contract"));
    assert!(!result.rationale.contains("synthesized fallback"));
    assert_eq!(result.cost_usd, 0.02);
    assert!(!result.cost_usd_exact);
}

#[test]
fn missing_assessment_cannot_become_a_false_positive() {
    let result = review(json!({"rationale": "More context needed", "confidence": 0.9}));
    assert_eq!(result.verdict, TriageVerdict::NeedsReview);
}

#[test]
fn canary_no_caller_refutation_stays_unresolved() {
    for first_link in [Value::Null, json!(""), json!("  ")] {
        let result = review(json!({
            "triggerable": false,
            "confidence": 0.67,
            "rationale": "The local overflow pattern is real, but no caller was found.",
            "refute_reason": "implausible_trigger",
            "first_link": first_link
        }));
        assert_eq!(result.verdict, TriageVerdict::NeedsReview);
        assert_eq!(result.refute_reason, None);
        assert_eq!(result.first_link, None);
        assert!(result.rationale.contains("no inspected call path"));
        assert!(result.rationale.contains("overflow pattern is real"));
    }
}

#[test]
fn inspected_trigger_refutation_retains_its_evidence() {
    let result = review(json!({
        "triggerable": false,
        "confidence": 0.9,
        "rationale": "The sole caller supplies the fixed valid frame.",
        "refute_reason": "implausible_trigger",
        "first_link": "  src/driver.c:40  "
    }));
    assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    assert_eq!(
        result.refute_reason,
        Some(crate::findings::RefuteReason::ImplausibleTrigger)
    );
    assert_eq!(result.first_link.as_deref(), Some("src/driver.c:40"));
    assert!(!result.rationale.contains("needs review"));
}

#[test]
fn a_guard_in_the_inspected_function_does_not_require_a_caller() {
    let result = review(json!({
        "triggerable": false,
        "confidence": 0.9,
        "rationale": "The size check in the same function rejects oversized input.",
        "refute_reason": "already_handled",
        "first_link": null
    }));
    assert_eq!(result.verdict, TriageVerdict::FalsePositive);
    assert_eq!(
        result.refute_reason,
        Some(crate::findings::RefuteReason::AlreadyHandled)
    );
}

#[test]
fn positive_and_low_confidence_boolean_contracts_remain_supported() {
    for (triggerable, confidence, expected) in [
        (true, 0.9, TriageVerdict::TruePositive),
        (true, 0.4, TriageVerdict::NeedsReview),
        (false, 0.4, TriageVerdict::NeedsReview),
    ] {
        let result = review(json!({
            "triggerable": triggerable,
            "confidence": confidence,
            "rationale": "source-linked assessment"
        }));
        assert_eq!(result.verdict, expected);
    }
}
