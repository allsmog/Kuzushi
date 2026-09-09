use crate::modules::ModuleRegistry;
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn map_outputs(tool: &str, input: Value) -> (Value, Value) {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(
        target.path().join("main.py"),
        "def hello():\n    return 'hello'\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
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
    let context = registry
        .execute_tool("context:build", json!({}), &ctx)
        .unwrap();
    let result = registry.execute_tool(tool, input, &ctx).unwrap();
    assert_eq!(result["status"], "completed");
    (context, result)
}

fn assert_shared_snapshot(context: Value, result: Value) {
    let expected = context.pointer("/data/snapshotHash").unwrap();
    assert!(expected.as_str().is_some_and(|hash| hash.len() == 64));
    assert_eq!(result.pointer("/data/snapshotHash"), Some(expected));
    assert_eq!(
        result.pointer("/data/treeHash"),
        context.pointer("/data/treeHash")
    );
}

#[test]
fn entry_point_result_carries_the_registered_map_source_identity() {
    let (context, result) = map_outputs("entry-points:extract", json!({}));
    assert!(result
        .pointer("/data/provenance/contextSnapshotSha256")
        .is_some());
    assert_shared_snapshot(context, result);
}

#[test]
fn recommendation_result_carries_the_registered_map_source_identity() {
    let (context, result) = map_outputs(
        "module-recommender:recommend",
        json!({"useModelRanking":false}),
    );
    assert!(result.pointer("/data/recommendations").unwrap().is_array());
    assert_shared_snapshot(context, result);
}
