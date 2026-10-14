use super::*;
use serde_json::json;

fn evidence() -> StudyResourceEvidenceV1 {
    serde_json::from_value(json!({
        "schemaVersion":1,"baselineCampaignId":"owned-prior","baselinePlanSha256":"sha256:recorded",
        "cases":[
            {"caseId":"app","equivalenceSha256":"app-conditions","passes":3,"runIds":["owned-app"],"callsPerPass":[2,4],"costPerPassUsd":[1.0,2.0],"limitations":[]},
            {"caseId":"shared","equivalenceSha256":"shared-conditions","passes":3,"runIds":["owned-shared"],"callsPerPass":[3,5],"costPerPassUsd":[1.0,2.0],"limitations":[]}
        ]
    })).unwrap()
}

#[test]
fn all_cases_and_maximum_starts_contribute_to_the_historical_scenario() {
    let result = evidence().project(2).unwrap();
    assert_eq!(result.starts, 12);
    assert_eq!(result.provider_calls, Some([30, 54]));
    assert_eq!(result.cost_usd, Some([12.0, 24.0]));
    assert_eq!(result.uncalibrated_cases, 0);
}

#[test]
fn unknown_requests_and_prices_never_make_an_incomplete_total_look_free() {
    let mut evidence = evidence();
    evidence.cases[1].calls_per_pass = None;
    evidence.cases[1].cost_per_pass_usd = None;
    let result = evidence.project(1).unwrap();
    assert_eq!(result.provider_calls, None);
    assert_eq!(result.cost_usd, None);
    assert_eq!(result.uncalibrated_cases, 1);
}

#[test]
fn call_scenarios_remain_available_when_only_prices_are_missing() {
    let mut evidence = evidence();
    evidence.cases[0].cost_per_pass_usd = None;
    let result = evidence.project(1).unwrap();
    assert_eq!(result.provider_calls, Some([15, 27]));
    assert_eq!(result.cost_usd, None);
}

#[test]
fn invalid_workload_and_future_versions_are_refused() {
    let mut evidence = evidence();
    assert!(evidence.project(0).is_err());
    assert!(evidence.project(11).is_err());
    evidence.cases[0].passes = 99;
    assert!(evidence.project(1).is_err());
    evidence.schema_version = 2;
    assert!(evidence.project(1).is_err());
}

#[test]
fn malformed_historical_ranges_are_refused_or_remain_unavailable() {
    let mut evidence = evidence();
    evidence.cases[0].calls_per_pass = Some([5, 4]);
    assert!(evidence.project(1).is_err());
    evidence.cases[0].calls_per_pass = Some([2, 4]);
    evidence.cases[0].cost_per_pass_usd = Some([
        Number::from_f64(4.0).unwrap(),
        Number::from_f64(2.0).unwrap(),
    ]);
    assert!(evidence.project(1).unwrap().cost_usd.is_none());
}

#[test]
fn projection_does_not_mutate_frozen_observations() {
    let evidence = evidence();
    let before = evidence.clone();
    evidence.project(3).unwrap();
    assert_eq!(evidence, before);
}
