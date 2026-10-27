use super::failure::{failed_scope, publish};
use super::*;

fn candidate() -> Value {
    json!({"schemaVersion":1,"scopes":[{"id":"app","name":"Owned application",
        "paths":["main.py"],"rationale":"Labeled scope recovery fixture",
        "sharedDependencies":["undeclared"],"openQuestions":[]}],
        "sharedScope":null,"sharedDiscovery":false,"exclusions":[]})
}

fn retained() -> (tempfile::TempDir, ContextStudyReceipt) {
    let (root, receipt) = failed_scope();
    let raw = serde_json::to_string(&candidate()).unwrap();
    publish(
        root.path(),
        "rejected-scope-output.json",
        &json!({"schemaVersion":1,
        "candidate":raw,"complete":true,"originalBytes":raw.len(),"reason":"undeclared scope"}),
    );
    (root, receipt)
}

fn recover(root: &Path, reference: Value, draft: Value) -> Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    ModuleRegistry::with_v2_builtins().execute_tool(
        "pack:scopes",
        json!({"operation":"recover","recoveryRef":reference,"draft":draft}),
        &context(&workspace, &config),
    )
}

#[test]
fn manual_scope_correction_is_runtime_free_unaccepted_and_preserves_failed_history() {
    let (root, receipt) = retained();
    let output = receipt.rejected_scope_draft(root.path()).unwrap().unwrap();
    let reference = serde_json::to_value(&output.reference).unwrap();
    assert!(recover(root.path(), reference.clone(), candidate()).is_err());
    let mut corrected = candidate();
    corrected["scopes"][0]["sharedDependencies"] = json!([]);
    let result = recover(root.path(), reference, corrected.clone()).unwrap();
    let review: crate::workspace::ScanScopeReview =
        serde_json::from_value(result["data"].clone()).unwrap();
    assert_eq!(review.reference.revision, 2);
    assert_eq!(
        serde_json::to_value(&review.record.draft).unwrap(),
        corrected
    );
    assert!(review.record.acceptance.is_none() && review.record.generation.is_none());
    assert_eq!(
        review.record.correction.as_ref().unwrap().rejected,
        output.reference
    );
    assert_eq!(review.coverage.uncovered_files.total, 0);
    assert!(receipt.generated_scopes(root.path()).is_err());
    assert!(receipt.rejected_scope_draft(root.path()).unwrap().is_some());
    assert_eq!(receipt.corrected_scopes(root.path()).unwrap(), Some(review));
}

#[test]
fn scope_recovery_refuses_drift_tampering_partial_output_and_silent_workload_changes() {
    for damage in [
        "source",
        "head",
        "artifact",
        "input",
        "partial",
        "reference",
        "exclusions",
        "shared",
    ] {
        let (root, receipt) = retained();
        let output = receipt.rejected_scope_draft(root.path()).unwrap().unwrap();
        let mut reference = serde_json::to_value(output.reference).unwrap();
        let mut corrected = candidate();
        corrected["scopes"][0]["sharedDependencies"] = json!([]);
        match damage {
            "source" => std::fs::write(root.path().join("main.py"), "# changed\n").unwrap(),
            "head" => {
                let workspace = WorkspaceTarget::new(root.path()).unwrap();
                let original =
                    serde_json::from_value(receipt.input["proposalRef"].clone()).unwrap();
                crate::workspace::edit_scan_scope_proposal(
                    &context(&workspace, &V2Config::default()),
                    &original,
                    crate::workspace::ScanScopeEdit::WholeRepository,
                )
                .unwrap();
            }
            "artifact" => std::fs::write(
                root.path()
                    .join(".kuzushi/v3/runs/rejected-scope/rejected-scope-output.json"),
                "{}",
            )
            .unwrap(),
            "input" => publish(root.path(), "input.json", &json!({"model":"foreign:model"})),
            "partial" => {
                let raw = serde_json::to_string(&candidate()).unwrap();
                publish(
                    root.path(),
                    "rejected-scope-output.json",
                    &json!({"schemaVersion":1,
                    "candidate":raw,"complete":false,"originalBytes":raw.len(),"reason":"partial"}),
                );
                reference = serde_json::to_value(
                    receipt
                        .rejected_scope_draft(root.path())
                        .unwrap()
                        .unwrap()
                        .reference,
                )
                .unwrap();
            }
            "reference" => reference["planSha256"] = json!("sha256:foreign"),
            "exclusions" => {
                corrected["exclusions"] = json!([{"path":"main.py","reason":"model request"}])
            }
            _ => corrected["sharedDiscovery"] = json!(true),
        }
        assert!(
            recover(root.path(), reference, corrected).is_err(),
            "{damage}"
        );
    }
}

fn paid_retained() -> (tempfile::TempDir, ContextStudyReceipt) {
    let (root, receipt) = retained();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let result = approve(
        &ModuleRegistry::with_v2_builtins(),
        &context(&workspace, &config),
        approval(&receipt),
    )
    .unwrap();
    let snapshot: crate::allowance::AllowanceSnapshot =
        serde_json::from_value(result["data"]["allowance"].clone()).unwrap();
    let input = receipt.bound_input(&snapshot).unwrap();
    publish(root.path(), "input.json", &input);
    let reference: crate::allowance::AllowanceReferenceV1 =
        serde_json::from_value(input["allowanceRef"].clone()).unwrap();
    let plan = snapshot.work_plan.as_ref().unwrap();
    let job = &plan.jobs[0];
    let ledger = crate::SpendLimiter::open(workspace.findings_db_path()).unwrap();
    ledger
        .claim_work_attempt(&crate::allowance::WorkAttempt {
            reference: &reference,
            run_id: "rejected-scope",
            tool: &job.tool,
            input_sha256: &job.input_sha256,
            source_identity: &plan.source_identity,
            config_sha256: &plan.config_sha256,
        })
        .unwrap();
    let reservation = ledger
        .reserve_provider_call(&crate::allowance::AllowanceCall {
            investigation_id: reference.investigation_id,
            expected_revision: reference.revision,
            request_id: "offline-failed-scope".into(),
            run_id: "rejected-scope".into(),
            work_id: reference.work_id,
            model: MODEL.into(),
            work: crate::allowance::InvestigationWork::Context,
        })
        .unwrap();
    ledger
        .settle_provider_call(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)
        .unwrap();
    (root, receipt)
}

fn corrected_review(
    root: &Path,
    receipt: &ContextStudyReceipt,
) -> crate::workspace::ScanScopeReview {
    let reference = receipt
        .rejected_scope_draft(root)
        .unwrap()
        .unwrap()
        .reference;
    let mut draft = candidate();
    draft["scopes"][0]["sharedDependencies"] = json!([]);
    serde_json::from_value(
        recover(root, serde_json::to_value(reference).unwrap(), draft).unwrap()["data"].clone(),
    )
    .unwrap()
}

#[test]
fn corrected_scope_planning_retains_spent_calls_and_the_original_investigation() {
    let (root, receipt) = paid_retained();
    let review = corrected_review(root.path(), &receipt);
    let snapshot = crate::capabilities::campaign::load_scope_proposal_allowance(
        root.path(),
        &review.reference,
    )
    .unwrap()
    .expect("manual correction must retain the paid investigation");
    assert_eq!(snapshot.investigation_id, receipt.investigation_id);
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 2);
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let accepted = crate::workspace::accept_scan_scope_proposal(
        &ctx,
        &review.reference,
        crate::workspace::ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let edited = crate::workspace::edit_scan_scope_proposal(
        &ctx,
        &accepted.reference,
        crate::workspace::ScanScopeEdit::Rename {
            scope_id: "app".into(),
            name: "Operator app".into(),
        },
    )
    .unwrap();
    for reference in [&review.reference, &accepted.reference, &edited.reference] {
        assert_eq!(
            crate::capabilities::campaign::load_scope_proposal_allowance(root.path(), reference)
                .unwrap()
                .unwrap(),
            snapshot
        );
    }
    let _store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let output = ModuleRegistry::with_v2_builtins().execute_tool("campaign:study", json!({
        "campaignId":"corrected-scan-draft", "scanInput":{"taskMode":"manual", "tasks":["secret-scan"],
        "threatModelRef":null, "scanScopeRef":{"proposal":accepted.reference,"scopeId":"app"}}
    }), &ctx).unwrap();
    assert_eq!(output["data"]["investigationId"], receipt.investigation_id);
    assert_eq!(output["data"]["approvalRequired"], true);
    assert_eq!(
        receipt.load_allowance(root.path()).unwrap().unwrap(),
        snapshot
    );
    assert!(!campaign_queue_path(root.path(), "corrected-scan-draft").exists());
}

#[test]
fn corrected_scope_accounting_damage_refuses_instead_of_starting_a_new_investigation() {
    for damage in ["artifact", "input-allowance", "missing-ledger"] {
        let (root, receipt) = paid_retained();
        let review = corrected_review(root.path(), &receipt);
        match damage {
            "artifact" => std::fs::write(
                root.path()
                    .join(".kuzushi/v3/runs/rejected-scope/rejected-scope-output.json"),
                "{}",
            )
            .unwrap(),
            "input-allowance" => {
                let mut input = crate::run_artifacts::load_authenticated_run_input(
                    root.path(),
                    "rejected-scope",
                )
                .unwrap();
                input["allowanceRef"]["investigationId"] = json!("foreign-investigation");
                publish(root.path(), "input.json", &input);
            }
            _ => std::fs::remove_file(root.path().join(".kuzushi/v3/index.sqlite3")).unwrap(),
        }
        assert!(
            crate::capabilities::campaign::load_scope_proposal_allowance(
                root.path(),
                &review.reference
            )
            .is_err(),
            "{damage}"
        );
    }
}
