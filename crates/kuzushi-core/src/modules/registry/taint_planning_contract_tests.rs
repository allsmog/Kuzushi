use crate::modules::{ModuleMaturity, RuntimeRequirement};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn missing_inventory_result(tool: &str) -> Value {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(
            tool,
            json!({"backend":"structural","discoverSignals":false}),
            &ctx,
            None,
        )
        .unwrap();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn planning_is_auxiliary_and_its_duplicate_surface_is_compatibility() {
    let registry = ModuleRegistry::with_v2_builtins();
    for (name, maturity) in [
        ("taint-iris-next:dataflow-plan", ModuleMaturity::Labs),
        (
            "taint-iris-next:source-sink-trace",
            ModuleMaturity::Compatibility,
        ),
    ] {
        let descriptor = registry.resolve_tool(name).unwrap();
        assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
        assert_eq!(descriptor.discovery_maturity, Some(maturity));
        assert!(!descriptor.phase_result);
        assert!(!registry.tool_is_discoverable(name));
    }
}

#[test]
fn missing_inventory_is_an_honest_failed_result_on_both_exact_interfaces() {
    for name in [
        "taint-iris-next:dataflow-plan",
        "taint-iris-next:source-sink-trace",
    ] {
        let result = missing_inventory_result(name);
        assert_eq!(result["status"], "failed");
        assert_eq!(result["data"]["status"], "missing-context");
        assert_eq!(result["data"]["missing"]["context"], true);
        assert_eq!(result["summary"], "Missing context or source inventory");
        assert!(result["output"]
            .as_str()
            .unwrap()
            .contains("Run context:build"));
    }
}
