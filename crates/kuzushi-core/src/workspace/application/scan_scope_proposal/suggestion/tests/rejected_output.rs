use super::*;

fn invalid_draft() -> Value {
    let mut value = draft();
    value["scopes"][0]["sharedDependencies"] = json!(["undeclared-contracts"]);
    value["scopes"][0]["rationale"] = json!("LABELED_PRIVATE_REJECTED_SCOPE");
    value
}

#[test]
fn explicitly_retained_scope_failure_keeps_candidate_private_and_spending_consumed() {
    let fixture = Fixture::new();
    let value = invalid_draft();
    let runtime = OfflineScopeRuntime::new(value.clone());
    let mut input = fixture.input();
    input["saveRejectedOutput"] = json!(true);
    let error = fixture.dispatch(input, &runtime).unwrap_err();
    assert!(
        error.to_string().contains("undeclared-contracts"),
        "normal CLI error formatting must keep the validation cause"
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    let message = format!("{error:#}");
    assert!(message.contains("undeclared-contracts"));
    assert!(!message.contains("LABELED_PRIVATE_REJECTED_SCOPE"));
    let path = fixture
        .workspace
        .root()
        .join(".kuzushi/v3/runs/scope-test/rejected-scope-output.json");
    let saved: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(saved["candidate"].as_str().unwrap()).unwrap(),
        value
    );
    assert_eq!(saved["complete"], true);
    assert_eq!(
        load_latest_scan_scope_proposal(&fixture.context())
            .unwrap()
            .unwrap(),
        fixture.original
    );
    let ledger = crate::SpendLimiter::open(fixture.workspace.findings_db_path()).unwrap();
    assert_eq!(
        ledger.allowance_snapshot("scopes").unwrap().committed_calls,
        1
    );
}

#[test]
fn ordinary_scope_failure_does_not_retain_private_model_text() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(invalid_draft());
    fixture.dispatch(fixture.input(), &runtime).unwrap_err();
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(!fixture
        .workspace
        .root()
        .join(".kuzushi/v3/runs/scope-test/rejected-scope-output.json")
        .exists());
}

#[test]
fn oversized_and_partial_scope_text_stays_bounded_without_becoming_a_valid_revision() {
    for partial in [false, true] {
        let fixture = Fixture::new();
        let mut runtime = OfflineScopeRuntime::new(draft());
        runtime.response.structured = None;
        runtime.response.text = if partial {
            serde_json::to_string(&draft()).unwrap()
        } else {
            "界".repeat(9000)
        };
        runtime.response.truncated = partial;
        let mut input = fixture.input();
        input["saveRejectedOutput"] = json!(true);
        fixture.dispatch(input, &runtime).unwrap_err();
        let raw = std::fs::read(
            fixture
                .workspace
                .root()
                .join(".kuzushi/v3/runs/scope-test/rejected-scope-output.json"),
        )
        .unwrap();
        let saved: crate::workspace::RejectedScopeCandidate = serde_json::from_slice(&raw).unwrap();
        saved.validate().unwrap();
        assert!(!saved.complete);
        assert!(saved.candidate.len() <= crate::workspace::MAX_REJECTED_SCOPE_BYTES);
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(
            load_latest_scan_scope_proposal(&fixture.context())
                .unwrap()
                .unwrap(),
            fixture.original
        );
    }
}

#[test]
fn saving_rejected_output_never_publishes_a_diagnostic_for_a_valid_scope_result() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(draft());
    let mut input = fixture.input();
    input["saveRejectedOutput"] = json!(true);
    fixture.dispatch(input, &runtime).unwrap();
    assert!(!fixture
        .workspace
        .root()
        .join(".kuzushi/v3/runs/scope-test/rejected-scope-output.json")
        .exists());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}
