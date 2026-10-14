use super::*;
use serde_json::json;

fn input() -> Value {
    json!({"baselineCaseId":"base", "contextCases":[
        {"id":"base","label":"Baseline","threatModelRef":null},
        {"id":"candidate","label":"Operator context", "passes":3,
            "threatModelRef":{"modelId":format!("tm_{}", "a".repeat(32)),"revisionId":format!("tmr_{}", "b".repeat(32)),"sha256":format!("sha256:{}", "a".repeat(64))}}
    ]})
}

#[test]
fn matrix_has_an_explicit_baseline_and_defaults_to_three_repetitions_per_case() {
    let draft = ContextMatrixDraft::from_input(&input()).unwrap().unwrap();
    assert_eq!(draft.job_count(), 6);
    assert_eq!(draft.baseline().unwrap().id, "base");
    assert_eq!(draft.cases[1].passes, 3);
    assert!(ContextMatrixDraft::from_input(&json!({}))
        .unwrap()
        .is_none());
    let mut changed = input();
    changed["trials"] = json!(2);
    assert_eq!(
        ContextMatrixDraft::from_input(&changed)
            .unwrap()
            .unwrap()
            .job_count(),
        5
    );
}

#[test]
fn malformed_unbounded_duplicate_and_implicit_conditions_are_rejected() {
    for defect in [
        "no-baseline",
        "foreign-baseline",
        "one-case",
        "too-many-cases",
        "too-many-jobs",
        "zero-passes",
        "overflow-passes",
        "duplicate-id",
        "duplicate-context",
        "active-context",
        "control-label",
        "oversize-label",
        "unsafe-id",
        "unknown-case-key",
        "historical-baseline",
    ] {
        let mut value = input();
        match defect {
            "no-baseline" => {
                value.as_object_mut().unwrap().remove("baselineCaseId");
            }
            "foreign-baseline" => value["baselineCaseId"] = json!("missing"),
            "one-case" => {
                value["contextCases"].as_array_mut().unwrap().pop();
            }
            "too-many-cases" => {
                value["contextCases"] = json!(vec![value["contextCases"][0].clone(); 9])
            }
            "too-many-jobs" => {
                value["contextCases"][0]["passes"] = json!(100);
            }
            "zero-passes" => value["contextCases"][1]["passes"] = json!(0),
            "overflow-passes" => value["contextCases"][1]["passes"] = json!(u64::MAX),
            "duplicate-id" => value["contextCases"][1]["id"] = json!("base"),
            "duplicate-context" => value["contextCases"][1]["threatModelRef"] = Value::Null,
            "active-context" => {
                value["contextCases"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("threatModelRef");
            }
            "control-label" => value["contextCases"][1]["label"] = json!("bad\nlabel"),
            "oversize-label" => value["contextCases"][1]["label"] = json!("x".repeat(257)),
            "unsafe-id" => value["contextCases"][1]["id"] = json!("../outside"),
            "unknown-case-key" => value["contextCases"][1]["subdivide"] = json!(true),
            _ => value["contextBaselineRunId"] = json!("historical-run"),
        }
        assert!(ContextMatrixDraft::from_input(&value).is_err(), "{defect}");
    }
    assert!(ContextMatrixDraft::from_input(&json!({"baselineCaseId":"base"})).is_err());
}
