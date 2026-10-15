use super::*;

fn recorded_response(child_results: Vec<Result<Value>>) -> Value {
    let entry = crate::capabilities::threat_intel::parse_catalog_str(
        "[[entry]]\nid='owned'\ncwe='CWE-20'\nseverity='low'\nhunt='taint-iris-next'\n[entry.taint_iris_next]\ntaint_class='owned-metadata'\n",
        Path::new("owned-metadata.toml"),
    )
    .unwrap()
    .remove(0);
    let entries: Vec<_> = (0..child_results.len())
        .map(|index| {
            let mut entry = entry.clone();
            entry.id = format!("owned-{index}");
            entry
        })
        .collect();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let mut results = child_results.into_iter();
    let applied = apply_threat_intel_entries(
        &entries,
        &ctx,
        None,
        true,
        |_, _, _, _| results.next().unwrap(),
        None,
    );
    threat_intel_apply_response(
        Path::new("owned-metadata.toml"),
        entries.len(),
        applied.results,
        applied.stats,
        false,
    )
}

#[test]
fn dispatch_errors_do_not_become_completed_catalog_runs() {
    let result = recorded_response(vec![Err(anyhow::anyhow!("Owned metadata refusal"))]);
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["summary"]["failed"], 1);
}

#[test]
fn failed_child_envelopes_remain_failed_and_are_retained() {
    let child = json!({"ok":false,"status":"failed","errors":["Owned metadata refusal"]});
    let result = recorded_response(vec![Ok(child.clone())]);
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["summary"]["failed"], 1);
    assert_eq!(result["data"]["entries"][0]["tool_result"], child);
}

#[test]
fn partial_child_observations_remain_readable_in_a_partial_parent() {
    let child = json!({"ok":true,"status":"partial","data":{"count":1}});
    let result = recorded_response(vec![Ok(child.clone())]);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["summary"]["partial"], 1);
    assert_eq!(result["data"]["summary"]["totalFindings"], 1);
    assert_eq!(result["data"]["entries"][0]["tool_result"], child);
}

#[test]
fn mixed_child_receipts_keep_completed_data_and_disclose_failure() {
    let completed = json!({"ok":true,"status":"completed","data":{"count":2}});
    let result = recorded_response(vec![
        Ok(completed.clone()),
        Err(anyhow::anyhow!("Owned metadata refusal")),
    ]);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["summary"]["failed"], 1);
    assert_eq!(result["data"]["summary"]["totalFindings"], 2);
    assert_eq!(result["data"]["entries"][0]["tool_result"], completed);
}

#[test]
fn skipped_child_receipts_are_not_counted_as_dispatched_work() {
    let child =
        json!({"ok":true,"status":"skipped","warnings":["Owned metadata has no prerequisite"]});
    let result = recorded_response(vec![Ok(child.clone())]);
    assert_eq!(result["data"]["summary"]["dispatched"], 0);
    assert_eq!(result["data"]["summary"]["skipped"], 1);
    assert_eq!(result["data"]["summary"]["dispatchRequests"], 1);
    assert_eq!(result["data"]["entries"][0]["status"], "skipped");
    assert_eq!(result["data"]["entries"][0]["tool_result"], child);
}
