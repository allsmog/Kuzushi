use super::*;

#[test]
fn generation_supplies_the_captured_observation_instead_of_changed_current_source() {
    let fixture = Fixture::new();
    let captured = std::fs::read_to_string(fixture.root.path().join("hello.txt")).unwrap();
    std::fs::write(
        fixture.root.path().join("hello.txt"),
        "Current-only source marker. Never executed.\n",
    )
    .unwrap();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    let result = fixture
        .dispatch(
            "findings:lesson-generate",
            fixture.input(),
            Some(&runtime),
            true,
        )
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let payload: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    assert_eq!(payload["capturedSource"]["status"], "included");
    assert_eq!(payload["capturedSource"]["text"], captured);
    assert_eq!(payload["capturedSource"]["currentSourceRead"], false);
    assert!(!requests[0].prompt.contains("Current-only source marker"));
    assert_eq!(
        result["data"]["lesson"]["generation"]["sourceCapture"],
        "included"
    );
    assert_eq!(
        result["data"]["lesson"]["generation"]["inputBytes"],
        requests[0].prompt.len()
    );
    assert_eq!(fixture.store.list_all_review_decisions().unwrap().len(), 1);
}
