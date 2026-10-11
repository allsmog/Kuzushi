use super::*;

fn input(cases: Value) -> Value {
    json!({"scopeProposalRef":{"proposalId":"owned","revision":1,"recordHash":"a".repeat(64)},"scopeCases":cases,"scanInput":{},"trials":3})
}

#[test]
fn explicit_scope_cases_freeze_their_pass_count_without_recursive_work() {
    let draft = ScopeStudyDraft::from_input(&input(
        json!([{"scopeId":"app"},{"scopeId":"shared","passes":2}]),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(draft.job_count(), 5);
    assert_eq!(draft.cases[0].passes, 3);
    assert!(draft.cases[0].threat_model_ref.is_none());
}

#[test]
fn oversized_duplicate_and_mixed_experiments_are_refused() {
    for cases in [
        json!([]),
        json!([{"scopeId":"app"},{"scopeId":"app"}]),
        json!([{"scopeId":"app","passes":101}]),
        json!([{"scopeId":"app","passes":60},{"scopeId":"other","passes":60}]),
    ] {
        assert!(ScopeStudyDraft::from_input(&input(cases)).is_err());
    }
    let mut value = input(json!([{"scopeId":"app"}]));
    value["contextCases"] = json!([]);
    assert!(ScopeStudyDraft::from_input(&value).is_err());
}

#[test]
fn omitted_and_explicitly_omitted_context_have_distinct_bindings() {
    let draft = ScopeStudyDraft::from_input(&input(
        json!([{"scopeId":"app"},{"scopeId":"other","threatModelRef":null}]),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(draft.cases[0].threat_model_ref, None);
    assert_eq!(draft.cases[1].threat_model_ref, Some(Value::Null));
}
