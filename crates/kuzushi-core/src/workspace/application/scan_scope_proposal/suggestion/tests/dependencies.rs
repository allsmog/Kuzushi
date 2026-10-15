use super::*;

#[test]
fn declared_shared_context_does_not_duplicate_primary_discovery() {
    let fixture = Fixture::new();
    let mut value = draft();
    value["sharedScope"] = json!({
        "id":"architecture", "name":"Shared architecture", "paths":["README.md"],
        "rationale":"Common context for the application.",
        "sharedDependencies":[], "openQuestions":[]
    });
    value["scopes"][0]["sharedDependencies"] = json!(["architecture"]);
    let runtime = OfflineScopeRuntime::new(value);
    let output = fixture.dispatch(fixture.input(), &runtime).unwrap();
    let review: ScanScopeReview = serde_json::from_value(output["data"].clone()).unwrap();
    assert_eq!(review.coverage.uncovered_files.total, 0);
    assert_eq!(review.coverage.overlaps.total, 0);
    assert_eq!(review.coverage.context_members["architecture"].total, 1);
    assert!(!review
        .coverage
        .discovery_members
        .contains_key("architecture"));
    assert_eq!(review.coverage.discovery_members["root"].total, 1);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(review.record.acceptance.is_none());
}

#[test]
fn undeclared_package_dependency_explains_the_failed_scope_without_repair() {
    let fixture = Fixture::new();
    let mut value = draft();
    value["scopes"][0]["sharedDependencies"] = json!(["greeting"]);
    let runtime = OfflineScopeRuntime::new(value);
    let error = fixture.dispatch(fixture.input(), &runtime).unwrap_err();
    let reason = format!("{error:#}");
    assert!(reason.contains("scope app references unknown scope id greeting"));
    assert!(reason.contains("ids declared in scopes or sharedScope"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
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
fn request_explains_scope_id_references_and_context_only_membership() {
    let fixture = Fixture::new();
    let runtime = OfflineScopeRuntime::new(draft());
    fixture.dispatch(fixture.input(), &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    let request = &requests[0];
    assert!(request
        .system_prompt
        .contains("must exactly match another id"));
    assert!(request
        .system_prompt
        .contains("sharedScope supplies context only"));
    let schema: Value = serde_json::from_str(include_str!("../output.schema.json")).unwrap();
    assert!(
        schema["$defs"]["scope"]["properties"]["sharedDependencies"]["description"]
            .as_str()
            .unwrap()
            .contains("Exact ids")
    );
    assert_eq!(
        schema["$defs"]["scope"]["properties"]["id"]["pattern"],
        "^[A-Za-z0-9_-]+$"
    );
}
