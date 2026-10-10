use super::*;
use crate::findings::{Finding, FindingRelationshipKind, Severity};
use crate::{V2Config, WorkspaceTarget};

#[test]
fn page_counts_reject_negative_and_fractional_values() {
    assert_eq!(page_count(&json!({}), "limit", 50).unwrap(), 50);
    assert_eq!(page_count(&json!({"offset":2}), "offset", 0).unwrap(), 2);
    assert!(page_count(&json!({"limit":-1}), "limit", 50).is_err());
    assert!(page_count(&json!({"offset":0.5}), "offset", 0).is_err());
}

#[test]
fn relationship_tools_use_prepared_dispatch_without_changing_finding_truth() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    for (run, rule) in [("relation-a", "a"), ("relation-b", "b")] {
        store
            .with_run_lifecycle(run, root.path(), || {
                store.insert_finding(
                    run,
                    &Finding::new_tool(
                        "owned-fixture",
                        rule,
                        "hello.txt",
                        1,
                        None,
                        Severity::Info,
                        "Labeled synthetic observation",
                    ),
                )?;
                Ok(((), 1))
            })
            .unwrap();
    }
    let rows = store.list_all_findings().unwrap();
    let proposal = store
        .propose_finding_relationship(
            rows[0].id.unwrap(),
            rows[1].id.unwrap(),
            FindingRelationshipKind::Duplicate,
            "Same labeled observation",
            Some(0.9),
        )
        .unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared=registry.prepare_dispatch_input("findings:relationship",json!({"id":proposal.id,"state":"accepted","note":"Reviewed the observations","expected_revision":1}),&ctx,None).unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["data"]["state"], "accepted");
    assert_eq!(store.list_all_findings().unwrap(), rows);
    assert!(store
        .latest_review_decisions_for_findings(&rows, true)
        .unwrap()
        .is_empty());
    let stale = registry
        .prepare_dispatch_input(
            "findings:relationship",
            json!({"id":proposal.id,"state":"removed","note":"Stale review","expectedRevision":1}),
            &ctx,
            None,
        )
        .unwrap();
    assert!(registry
        .dispatch_prepared_input_with_runtime(stale, &ctx, None)
        .is_err());
    assert!(registry
        .prepare_dispatch_input(
            "findings:relationship",
            json!({"unexpected":true}),
            &ctx,
            None
        )
        .is_err());
    let selected = store.finding_relationship(&proposal.id).unwrap().unwrap();
    let prepared = registry
        .prepare_dispatch_input(
            "findings:relationship-batch",
            json!({"relationships":[selected],"state":"removed","note":"Reviewed atomic undo"}),
            &ctx,
            None,
        )
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["data"]["records"][0]["revision"], 3);
    assert_eq!(result["data"]["records"][0]["state"], "removed");
    assert_eq!(store.list_all_findings().unwrap(), rows);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}
