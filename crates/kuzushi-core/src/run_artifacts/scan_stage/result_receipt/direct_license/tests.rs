use super::*;
use serde_json::json;

fn fixture() -> (Value, PhaseStageReceipt) {
    let receipt = json!({"phase":"scan","outcome":"completed","runRefs":["owned"],"scan":{
        "scope":{"target":"/owned"}, "plan":{"selection":"direct","engines":["license-scan"]},
        "engines":[{"engine":"license-scan","outcome":"complete","ruleIds":["license-scan/missing-license"]}],
        "findingDelta":{"added":0,"updated":0}, "durationMs":1,
        "targetSnapshot":{"target":"/owned","dirty":false}
    }});
    (
        json!({"status":"completed","data":{"target":"/owned"}}),
        serde_json::from_value(receipt).unwrap(),
    )
}

#[test]
fn direct_policy_coverage_cannot_claim_other_engines_paths_targets_or_outcomes() {
    let (output, valid) = fixture();
    validate(&output, Some(&valid)).unwrap();
    for edit in [
        "engine", "plan", "path", "target", "snapshot", "policy", "outcome", "count",
    ] {
        let mut receipt = valid.clone();
        let scan = receipt.scan.as_mut().unwrap();
        match edit {
            "engine" => scan.engines[0].engine = "secret-scan".into(),
            "plan" => scan.plan.engines = vec!["secret-scan".into()],
            "path" => scan.scope.paths = vec!["src".into()],
            "target" => scan.scope.target = "/another".into(),
            "snapshot" => scan.target_snapshot.target = "/another".into(),
            "policy" => scan.engines[0].rule_ids = None,
            "outcome" => scan.engines[0].outcome = ScanEngineStageOutcome::Partial,
            "count" => scan.engines.clear(),
            _ => unreachable!(),
        }
        assert!(validate(&output, Some(&receipt)).is_err(), "{edit}");
    }
}

#[test]
fn unsuccessful_results_cannot_claim_completed_policy_coverage() {
    let (mut output, receipt) = fixture();
    for status in ["failed", "skipped", "partial"] {
        output["status"] = json!(status);
        assert!(validate(&output, Some(&receipt)).is_err());
    }
    validate(&output, None).unwrap();
}
