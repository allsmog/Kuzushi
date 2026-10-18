use super::*;
use serde_json::{json, Value};

fn dispatch(ctx: &ToolExecutionContext<'_>, input: Value) -> Result<Value> {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input("pack:scopes", input, ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

#[test]
fn scope_dispatch_preserves_complete_enumeration_and_partial_inspection_through_acceptance() {
    let (dir, workspace, config) = target();
    fs::write(
        dir.path().join("large.rs"),
        b"// inert prefix\n".repeat(18000),
    )
    .unwrap();
    let ctx = context(&workspace, &config);
    let created = dispatch(&ctx, json!({"operation":"create"})).unwrap();
    let review: ScanScopeReview = serde_json::from_value(created["data"].clone()).unwrap();
    assert!(review.coverage.enumeration_complete);
    assert!(review.coverage.inventory_limited);
    assert_eq!(review.coverage.enumerated_files, 3);
    let read = dispatch(
        &ctx,
        json!({"operation":"read","proposalRef":review.reference}),
    )
    .unwrap();
    assert_eq!(read["data"], created["data"]);
    let mut accept = json!({"operation":"accept","proposalRef":review.reference,
        "acknowledgements":{"inventoryLimitations":false,"overlappingDiscovery":false,"exclusions":false}});
    assert!(dispatch(&ctx, accept.clone())
        .unwrap_err()
        .to_string()
        .contains("inventory limitations"));
    assert!(load_scan_scope_proposal(&workspace, &review.reference)
        .unwrap()
        .record
        .acceptance
        .is_none());
    accept["acknowledgements"]["inventoryLimitations"] = json!(true);
    let accepted = dispatch(&ctx, accept).unwrap();
    assert_eq!(accepted["data"]["coverage"]["enumerationComplete"], true);
    assert_eq!(accepted["data"]["coverage"]["inventoryLimited"], true);
    assert!(accepted["data"]["record"]["acceptance"].is_object());
    assert!(!workspace.state_dir().join("campaigns").exists());
}
