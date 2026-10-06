use super::*;
use crate::capabilities::campaign::load_scope_proposal_allowance;

fn saved_output(fixture: &Fixture) -> (ScanScopeReview, Value) {
    let output = fixture
        .dispatch(fixture.input(), &OfflineScopeRuntime::new(draft()))
        .unwrap();
    let review = serde_json::from_value(output["data"].clone()).unwrap();
    save_receipt(fixture, &output);
    (review, output)
}

fn receipt_path(fixture: &Fixture) -> std::path::PathBuf {
    fixture
        .workspace
        .state_dir()
        .join("runs/scope-test/result.json")
}

fn save_receipt(fixture: &Fixture, output: &Value) {
    let path = receipt_path(fixture);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(output).unwrap()).unwrap();
}

#[test]
fn operator_exclusions_survive_generated_boundaries_and_are_supplied_to_the_model() {
    let mut fixture = Fixture::new();
    fixture.original = edit_scan_scope_proposal(
        &fixture.context(),
        &fixture.original.reference,
        ScanScopeEdit::ExcludePath {
            path: "README.md".into(),
            reason: "Operator excluded fixture documentation".into(),
        },
    )
    .unwrap();
    let runtime = OfflineScopeRuntime::new(draft());
    let output = fixture.dispatch(fixture.input(), &runtime).unwrap();
    let review: ScanScopeReview = serde_json::from_value(output["data"].clone()).unwrap();
    assert_eq!(
        review.record.draft.exclusions,
        fixture.original.record.draft.exclusions
    );
    assert_eq!(review.coverage.excluded_files.total, 1);
    assert_eq!(review.coverage.uncovered_files.total, 0);
    let requests = runtime.requests.lock().unwrap();
    assert!(requests[0]
        .prompt
        .contains("Operator excluded fixture documentation"));
}

#[test]
fn generated_scope_accounting_survives_acceptance_and_operator_edits() {
    let fixture = Fixture::new();
    assert!(
        load_scope_proposal_allowance(fixture.root.path(), &fixture.original.reference)
            .unwrap()
            .is_none()
    );
    let (review, _) = saved_output(&fixture);
    let accepted = accept_scan_scope_proposal(
        &fixture.context(),
        &review.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let edited = edit_scan_scope_proposal(
        &fixture.context(),
        &accepted.reference,
        ScanScopeEdit::Rename {
            scope_id: "app".into(),
            name: "Operator application boundary".into(),
        },
    )
    .unwrap();
    for reference in [&review.reference, &accepted.reference, &edited.reference] {
        let snapshot = load_scope_proposal_allowance(fixture.root.path(), reference)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.investigation_id, "scopes");
        assert_eq!(snapshot.committed_calls, 1);
        assert_eq!(snapshot.limits.max_provider_calls, 2);
    }
}

#[test]
fn scope_backed_scan_draft_inherits_the_paid_investigation_without_new_approval() {
    let fixture = Fixture::new();
    let _store = crate::FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let (review, _) = saved_output(&fixture);
    let accepted = accept_scan_scope_proposal(
        &fixture.context(),
        &review.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let scope = crate::workspace::ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "app".into(),
    };
    let output = fixture.registry.execute_tool("campaign:study", json!({
        "campaignId":"scoped-scans", "scanInput":{"taskMode":"manual", "tasks":["secret-scan"],
        "threatModelRef":null, "scanScopeRef":scope}
    }), &fixture.context()).unwrap();
    assert_eq!(output["data"]["investigationId"], "scopes");
    assert_eq!(output["data"]["jobCount"], 3);
    assert_eq!(output["data"]["approvalRequired"], true);
    let snapshot = load_scope_proposal_allowance(fixture.root.path(), &review.reference)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.committed_calls, 1);
    assert!(snapshot.work_plan.is_none());
    assert!(!fixture
        .workspace
        .state_dir()
        .join("campaigns/scoped-scans/queue.json")
        .exists());
}

#[test]
fn missing_malformed_or_mismatched_generation_receipts_cannot_reset_accounting() {
    for damage in [
        "missing",
        "malformed",
        "different-proposal",
        "different-model",
        "missing-allowance",
        "newer-revision",
        "missing-investigation",
    ] {
        let fixture = Fixture::new();
        let (review, mut output) = saved_output(&fixture);
        match damage {
            "missing" => std::fs::remove_file(receipt_path(&fixture)).unwrap(),
            "malformed" => std::fs::write(receipt_path(&fixture), "invalid receipt").unwrap(),
            _ => {
                match damage {
                    "different-proposal" => {
                        output["data"]["reference"]["proposalId"] = json!("other")
                    }
                    "different-model" => {
                        output["data"]["record"]["generation"]["model"] = json!("other:model")
                    }
                    "missing-allowance" => {
                        output.as_object_mut().unwrap().remove("allowanceRef");
                    }
                    "newer-revision" => output["allowanceRef"]["revision"] = json!(99),
                    _ => output["allowanceRef"]["investigationId"] = json!("missing"),
                }
                save_receipt(&fixture, &output);
            }
        }
        assert!(
            load_scope_proposal_allowance(fixture.root.path(), &review.reference).is_err(),
            "{damage}"
        );
    }
}
