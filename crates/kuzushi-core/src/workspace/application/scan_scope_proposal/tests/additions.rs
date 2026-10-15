use super::*;
use serde_json::json;

#[test]
fn prepared_addition_clears_current_acceptance_and_preserves_accepted_history() {
    let (_root, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let registry = crate::modules::ModuleRegistry::with_v2_builtins();
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &original.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let input = json!({"operation":"edit","proposalRef":accepted.reference,
        "edit":{"action":"add-scope","scope":{"id":"root-review","name":"Root review",
        "paths":["root.rs"],"rationale":"Explicit overlapping integration review.",
        "sharedDependencies":[],"openQuestions":[]}}});
    let prepared = registry
        .prepare_dispatch_input("pack:scopes", input, &ctx, None)
        .unwrap();
    let output = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let after: ScanScopeReview = serde_json::from_value(output["data"].clone()).unwrap();
    assert!(after.record.acceptance.is_none());
    assert_eq!(after.coverage.overlaps.total, 1);
    assert_eq!(after.record.previous.as_ref(), Some(&accepted.reference));
    assert_eq!(
        load_accepted_scan_scope_proposal(&ctx, &accepted.reference).unwrap(),
        accepted
    );
    assert!(!workspace.state_dir().join("campaigns").exists());
}
