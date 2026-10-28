use super::*;
use serde_json::json;

#[test]
fn recorded_request_keeps_literal_values_and_excludes_unrelated_sensitive_input() {
    let input = json!({"taskMode":"manual","tasks":["semgrep"],
        "semgrepConfig":["p/owned", " rules \\\"λ\\\"\n.yaml "],"semgrepBinary":" local scanner ",
        "semgrepJobs":1,"semgrepTimeoutMs":60000,
        "prompt":"private prompt","apiKey":"private credential","threatModelRef":{"private":"context"}});
    let selection = from_input(Some("scope-λ"), &input);
    let value = serde_json::to_value(&selection).unwrap();
    assert_eq!(value["caseId"], "scope-λ");
    assert_eq!(value["parameters"]["semgrepConfig"], input["semgrepConfig"]);
    assert_eq!(value["parameters"]["semgrepBinary"], " local scanner ");
    assert_eq!(selection.parameters.len(), 6);
    assert!(!value.to_string().contains("private"));
}

#[test]
fn absent_null_empty_and_unrecognized_recorded_values_remain_distinct() {
    assert!(single(&json!({"prompt":"not a scan setting"})).is_empty());
    for value in [Value::Null, json!([]), json!({"unexpected":"format"})] {
        let selection = from_input(None, &json!({"semgrepConfig":value}));
        assert_eq!(selection.parameters.get("semgrepConfig"), Some(&value));
        assert!(!selection.parameters.contains_key("tasks"));
        assert!(serde_json::to_value(selection)
            .unwrap()
            .get("caseId")
            .is_none());
    }
}
