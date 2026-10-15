use super::*;

fn retained_fixture(root: &Path) -> FindingStore {
    seed_batch_documents(root);
    let expected = planned_config_sha256(root);
    for run in [
        "run-trial-1-a2",
        "run-trial-2-a1",
        "run-trial-3-a1",
        "run-trial-3-a2",
    ] {
        write_trial_receipt(root, run, &expected);
    }
    write_child_equivalence_receipt(root, "run-trial-1-a1");
    let record =
        crate::run_artifacts::ToolRunRecord::new(root, "run-trial-1-a1", "run", "sast:scan");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({}),
        None,
        Some(expected),
        vec![],
    )
    .unwrap();
    crate::run_artifacts::try_record_tool_run_canceled(record, "Labeled fixture cancellation")
        .unwrap();
    let queue_path = crate::capabilities::campaign::campaign_queue_path(root, "batch-test");
    let mut queue: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&queue_path).unwrap()).unwrap();
    for (id, total) in [("trial-001", 2), ("trial-002", 1), ("trial-003", 2)] {
        queue["jobs"][id]["attempts"] = json!(1);
        queue["jobs"][id]["dispatches"] = json!(total);
        queue["jobs"][id]["state"] = json!("completed");
    }
    std::fs::write(queue_path, queue.to_string()).unwrap();
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for run in ["run-trial-1-a1", "run-trial-1-a2", "run-trial-2-a1"] {
        store.record_run_started(run, root, "completed").unwrap();
    }
    store
}

fn signal(label: &str) -> Finding {
    let mut finding = Finding::new_tool(
        "owned-fixture",
        label,
        "source.rs",
        1,
        None,
        Severity::Info,
        &format!("Labeled {label} observation"),
    );
    finding.identity_id = Some(format!("fi_retained_{label}"));
    finding.identity_basis = Some(FindingIdentityBasis::ExactProducerFingerprint);
    finding
}

#[test]
fn canceled_only_observations_remain_visible_with_zero_completed_pass_recurrence() {
    let target = tempfile::tempdir().unwrap();
    let store = retained_fixture(target.path());
    let canceled = signal("canceled-only");
    let latest = signal("latest-only");
    let repeated = signal("repeated");
    store
        .insert_findings("run-trial-1-a1", &[canceled.clone(), repeated.clone()])
        .unwrap();
    store
        .insert_findings("run-trial-1-a2", &[latest.clone(), repeated.clone()])
        .unwrap();
    store.insert_finding("run-trial-2-a1", &repeated).unwrap();
    let before = serde_json::to_value(store.list_findings(100).unwrap()).unwrap();
    let report = derive_batch_occurrence_report(target.path(), "batch-test", &store).unwrap();
    let row = |finding: &Finding| {
        report
            .rows
            .iter()
            .find(|row| row.fingerprints.contains(&finding.fingerprint))
            .unwrap()
    };
    assert_eq!(row(&canceled).seen, 0);
    assert_eq!(row(&canceled).run_ids, ["run-trial-1-a1"]);
    assert!(row(&canceled).completed_pass_hint().is_some());
    assert_eq!(row(&latest).seen, 1);
    assert_eq!(row(&latest).run_ids, ["run-trial-1-a2"]);
    assert_eq!(row(&repeated).seen, 2);
    assert_eq!(
        row(&repeated).run_ids,
        ["run-trial-1-a1", "run-trial-1-a2", "run-trial-2-a1"]
    );
    assert_eq!(
        serde_json::to_value(store.list_findings(100).unwrap()).unwrap(),
        before
    );
    assert_eq!(
        report
            .retained_observation_fingerprints(target.path(), &store)
            .unwrap()
            .len(),
        3
    );
    assert!(report
        .output()
        .contains("Retained outside completed passes"));
}

#[test]
fn missing_a_later_retry_does_not_clear_retained_severity_gates() {
    let target = tempfile::tempdir().unwrap();
    let store = retained_fixture(target.path());
    let mut finding = signal("retained-high");
    finding.severity = Severity::High;
    store.insert_finding("run-trial-1-a1", &finding).unwrap();
    let report =
        derive_batch_occurrence_report_for_controller(target.path(), "batch-test", &store).unwrap();
    assert_eq!(report.rows[0].seen, 0);
    assert_eq!(
        derive_batch_gate_binding(&store, &report, Some(Severity::High), None)
            .unwrap()
            .1,
        1
    );
}

#[test]
#[ignore = "Writes explicitly labeled native reader history only when requested"]
fn native_retained_attempt_fixture() {
    let root = std::path::PathBuf::from(std::env::var_os("KUZUSHI_RETAINED_FIXTURE_ROOT").unwrap());
    assert_eq!(root.file_name().unwrap(), "fixture-target");
    assert!(root.join(".git").is_dir());
    let store = retained_fixture(&root);
    for (run, labels) in [
        ("run-trial-1-a1", vec!["canceled-only", "repeated"]),
        ("run-trial-1-a2", vec!["latest-only", "repeated"]),
        ("run-trial-2-a1", vec!["repeated"]),
        ("run-trial-3-a1", vec!["superseded-only"]),
    ] {
        store.record_run_started(run, &root, "completed").unwrap();
        for label in labels {
            store.insert_finding(run, &signal(label)).unwrap();
        }
    }
    let report = derive_batch_occurrence_report(&root, "batch-test", &store).unwrap();
    assert_eq!(report.completed, 3);
    let mut recurrence = report.rows.iter().map(|row| row.seen).collect::<Vec<_>>();
    recurrence.sort();
    assert_eq!(recurrence, [0, 0, 1, 2]);
    std::fs::write(
        root.join(".kuzushi/reader-fixture.json"),
        json!({"synthetic":true,"executorsInvoked":false,
        "providerRequests":0,"targetSourceExecuted":false,"observations":6,"findings":4})
        .to_string(),
    )
    .unwrap();
}
