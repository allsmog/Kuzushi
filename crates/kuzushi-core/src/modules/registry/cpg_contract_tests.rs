use crate::modules::{ModuleRegistry, RuntimeRequirement, ToolPhase};
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn dispatch(workspace: &WorkspaceTarget, input: Value) -> anyhow::Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("cpg:build", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn go_source(root: &std::path::Path, name: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("greeting.go"),
        format!("package greeting\nfunc {name}() string {{ return \"Hello\" }}\n"),
    )
    .unwrap();
}

#[test]
fn code_graphs_are_auxiliary_mapping_and_not_default_supported_work() {
    let registry = ModuleRegistry::with_v2_builtins();
    let descriptor = registry.resolve_tool("cpg:build").unwrap();
    assert_eq!(descriptor.phase, ToolPhase::Map);
    assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
    assert!(descriptor.headless);
    assert!(!descriptor.phase_result, "A graph is not accepted context");
    assert_eq!(crate::modules::phase_result_phase(descriptor), None);
    assert!(!registry
        .discoverable_tools()
        .any(|tool| tool.name == "cpg:build"));
}

#[cfg(feature = "private-cpg")]
#[test]
fn exact_graph_dispatch_builds_nonempty_artifacts_without_a_context_prerequisite() {
    let root = tempfile::tempdir().unwrap();
    go_source(root.path(), "Greeting");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({"languages":"go","maxSourceFiles":2})).unwrap();
    assert_eq!(result["status"], "completed");
    let graph = &result["data"]["graphs"][0];
    assert_eq!(graph["sourceFiles"], 1);
    assert!(graph["methods"].as_u64().unwrap() > 0);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("1 source file · 1 method, 0 calls"));
    let path = std::path::Path::new(graph["cpgPath"].as_str().unwrap());
    kuzushi_cpg::validate_graph_artifact(path).unwrap();
    let scope = kuzushi_cpg::BuildScope::whole(root.path());
    let project = kuzushi_cpg::open_project_in(&scope, "go").unwrap();
    assert!(kuzushi_cpg::queries::graph_stats(&project).methods > 0);
    assert!(!crate::context::context_snapshot_path(workspace.root()).exists());
}

#[cfg(feature = "private-cpg")]
#[test]
fn scoped_graphs_keep_sibling_source_out_and_artifacts_under_the_workspace() {
    let root = tempfile::tempdir().unwrap();
    go_source(&root.path().join("first"), "First");
    go_source(&root.path().join("second"), "Second");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({"subdir":"first","languages":"go"})).unwrap();
    let graph = &result["data"]["graphs"][0];
    assert_eq!(graph["sourceFiles"], 1);
    let path = std::path::Path::new(graph["cpgPath"].as_str().unwrap());
    assert!(path.starts_with(workspace.root().join(".kuzushi/cpg-rs/scoped")));
    assert!(!root.path().join("first/.kuzushi").exists());
    let scope =
        kuzushi_cpg::BuildScope::subtree(root.path(), std::path::Path::new("first")).unwrap();
    let project = kuzushi_cpg::open_project_in(&scope, "go").unwrap();
    assert!(kuzushi_cpg::queries::graph_stats(&project).methods > 0);
    assert!(!kuzushi_cpg::artifact_path(root.path(), "go").exists());
}

#[cfg(feature = "private-cpg")]
#[test]
fn prepared_graph_build_reuses_and_invalidates_captured_content() {
    let root = tempfile::tempdir().unwrap();
    go_source(root.path(), "Original");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let input = json!({"languages":"go"});
    assert_eq!(
        dispatch(&workspace, input.clone()).unwrap()["data"]["graphs"][0]["reusedCache"],
        false
    );
    assert_eq!(
        dispatch(&workspace, input.clone()).unwrap()["data"]["graphs"][0]["reusedCache"],
        true
    );
    go_source(root.path(), "Changed");
    assert_eq!(
        dispatch(&workspace, input).unwrap()["data"]["graphs"][0]["reusedCache"],
        false
    );
}

#[cfg(feature = "private-cpg")]
#[test]
fn graph_input_and_build_limits_refuse_without_widening_scope() {
    let root = tempfile::tempdir().unwrap();
    go_source(&root.path().join("first"), "First");
    go_source(&root.path().join("second"), "Second");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    for input in [
        json!({"scanScopeRef":{}}),
        json!({"subdir":"../outside"}),
        json!({"languages":"kotlin"}),
        json!({"maxSourceFiles":0}),
    ] {
        assert!(dispatch(&workspace, input).is_err());
    }
    let error = dispatch(&workspace, json!({"languages":"go","maxSourceFiles":1})).unwrap_err();
    assert!(format!("{error:#}").contains("cap of 1"));
    assert!(!kuzushi_cpg::artifact_path(root.path(), "go").exists());
}

#[cfg(feature = "private-cpg")]
#[test]
fn a_later_language_failure_retains_graphs_in_a_partial_receipt() {
    let root = tempfile::tempdir().unwrap();
    go_source(root.path(), "Greeting");
    std::fs::write(root.path().join("invalid.py"), [0xff]).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(&workspace, json!({"languages":"go,python"})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["graphs"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["graphs"][0]["language"], "go");
    assert!(result["data"]["stopReason"]
        .as_str()
        .unwrap()
        .contains("python"));
    assert!(result["output"].as_str().unwrap().contains("partial"));
}

#[cfg(feature = "private-cpg")]
#[test]
fn imports_refuse_ignored_build_options_and_do_not_assess_current_source() {
    let root = tempfile::tempdir().unwrap();
    go_source(root.path(), "Greeting");
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let built = dispatch(&workspace, json!({"languages":"go"})).unwrap();
    let path = built["data"]["graphs"][0]["cpgPath"].clone();
    for (key, value) in [
        ("languages", json!("python")),
        ("subdir", json!(".")),
        ("maxSourceFiles", json!(1)),
    ] {
        let mut input = json!({"importPath":path});
        input[key] = value;
        let error = dispatch(&workspace, input).unwrap_err();
        assert!(format!("{error:#}").contains("cannot be combined"));
    }
    let imported = dispatch(&workspace, json!({"importPath":path})).unwrap();
    assert_eq!(imported["status"], "completed");
    assert_eq!(
        imported["data"]["currentCheckoutApplicability"],
        "not_assessed"
    );
    assert!(imported["output"]
        .as_str()
        .unwrap()
        .contains("Source applicability: not assessed"));
}
