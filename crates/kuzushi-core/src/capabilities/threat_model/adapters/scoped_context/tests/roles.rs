use super::*;

#[test]
fn scoped_generated_role_rejection_keeps_one_spent_call_and_original_context() {
    let fixture = Fixture::new();
    let before = std::fs::read(
        fixture
            .root
            .path()
            .join(".kuzushi/threat-models/manifest.json"),
    )
    .unwrap();
    let receipt = fixture.plan("group-invalid-role");
    let input = fixture.approve(&receipt);
    let mut output = document();
    output["dfd"]["nodes"][0]["type"] = json!("data-type");
    let runtime = OfflineRuntime::new(output);
    let error = fixture
        .dispatch("threat-model:build", input, Some(&runtime), false)
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("/dfd/nodes/0/type") && text.contains("data-type"),
        "{text}"
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(
            fixture
                .root
                .path()
                .join(".kuzushi/threat-models/manifest.json")
        )
        .unwrap(),
        before
    );
    let allowance = receipt
        .load_allowance(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(allowance.committed_calls, 1);
    assert_eq!(allowance.protected_review_remaining(), 1);
    let (_, rejected) = crate::run_artifacts::read_run_artifact_text_bounded(
        fixture.root.path(),
        "scope-context-test",
        "rejected-context-output.txt",
        128 * 1024,
    )
    .unwrap();
    assert!(rejected.contains("data-type"));
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
}

#[test]
fn scoped_generated_role_rejection_cannot_fill_a_missing_type_after_a_paid_reply() {
    let fixture = Fixture::new();
    let receipt = fixture.plan("group-missing-role");
    let input = fixture.approve(&receipt);
    let mut output = document();
    output["dfd"]["nodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("type");
    let runtime = OfflineRuntime::new(output);
    let error = fixture
        .dispatch("threat-model:build", input, Some(&runtime), false)
        .unwrap_err();
    assert!(format!("{error:#}").contains("requires a text role"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        receipt
            .load_allowance(fixture.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
    assert_eq!(
        load_threat_model_manifest(fixture.root.path())
            .unwrap()
            .unwrap()
            .models
            .len(),
        1
    );
}
