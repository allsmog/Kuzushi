use crate::modules::ModuleRegistry;
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn context<'a>(workspace: &'a WorkspaceTarget, config: &'a V2Config) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn dispatch(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    input: Value,
) -> anyhow::Result<Value> {
    let prepared = registry.prepare_dispatch_input("pack:scopes", input, ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

#[test]
fn prepared_scope_proposal_dispatch_supports_review_edit_accept_and_file_paging_without_a_model() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("main.py"), "print('fixture')\n").unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    assert_eq!(
        crate::modules::phase_result_phase(registry.resolve_tool("pack:scopes").unwrap()),
        None
    );
    let created = dispatch(&registry, &ctx, json!({})).unwrap();
    let reference = created["data"]["reference"].clone();
    assert_eq!(created["data"]["coverage"]["enumeratedFiles"], 1);
    assert!(created["data"]["record"]["acceptance"].is_null());
    assert_read_and_page(&registry, &ctx, &created, &reference);
    let edited = dispatch(
        &registry,
        &ctx,
        json!({"operation":"edit", "proposalRef":reference,
        "edit":{"action":"rename", "scopeId":"repository", "name":"Application"}}),
    )
    .unwrap();
    assert_eq!(edited["data"]["reference"]["revision"], 2);
    assert_exact_acceptance(
        &registry,
        &ctx,
        reference,
        edited["data"]["reference"].clone(),
    );
    assert!(crate::strategy::load_strategy_queue(&workspace).unwrap()[0]
        .tool
        .is_none());
    assert!(!workspace.state_dir().join("campaigns").exists());
}

fn assert_exact_acceptance(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    stale: Value,
    current: Value,
) {
    let acknowledgements =
        json!({"inventoryLimitations":true,"overlappingDiscovery":false,"exclusions":false});
    assert!(dispatch(
        registry,
        ctx,
        json!({"operation":"accept", "proposalRef":stale, "acknowledgements":acknowledgements})
    )
    .is_err());
    let accepted = dispatch(
        registry,
        ctx,
        json!({"operation":"accept", "proposalRef":current, "acknowledgements":acknowledgements}),
    )
    .unwrap();
    assert!(accepted["data"]["record"]["acceptance"].is_object());
}

fn assert_read_and_page(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    created: &Value,
    reference: &Value,
) {
    let read = registry
        .execute_tool(
            "pack:scopes",
            json!({"operation":"read", "proposalRef":reference}),
            ctx,
        )
        .unwrap();
    assert_eq!(read["data"], created["data"]);
    let page = dispatch(
        registry,
        ctx,
        json!({"operation":"files", "proposalRef":reference,
        "fileFilter":{"kind":"scope", "scopeId":"repository"}, "pageSize":1}),
    )
    .unwrap();
    assert_eq!(page["data"]["files"], json!(["main.py"]));
}

#[test]
fn scope_descriptor_rejects_unknown_recursive_controls_and_unbounded_pages() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    for input in [
        json!({"recursive":true}),
        json!({"operation":"split-again"}),
        json!({"pageSize":129}),
        json!({"pageSize":0}),
        json!({"offset":-1}),
    ] {
        assert!(registry
            .prepare_dispatch_input("pack:scopes", input, &ctx, None)
            .is_err());
    }
    for input in [
        json!({"operation":"read"}),
        json!({"operation":"edit","proposalRef":{}}),
        json!({"operation":"create","acknowledgements":{}}),
    ] {
        assert!(dispatch(&registry, &ctx, input).is_err());
    }
    assert!(crate::strategy::load_strategy_queue(&workspace)
        .unwrap()
        .is_empty());
}
