use crate::modules::{ModuleMaturity, RuntimeRequirement};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

const OWNED_CATALOG: &str = r#"schema_version = "1"
[[entry]]
id = "owned-record"
title = "Labeled metadata only"
cwe = "CWE-20"
severity = "low"
hunt = "taint-iris-next"
[entry.taint_iris_next]
taint_class = "owned-metadata"
languages = ["text"]
source_signals = ["OwnedInput"]
sink_signals = ["OwnedRecord"]
[[entry]]
id = "owned-unsupported"
cwe = "CWE-20"
severity = "low"
hunt = "owned-inert"
"#;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".kuzushi/catalogs/owned.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, OWNED_CATALOG).unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        Self { root, workspace }
    }

    fn dispatch(&self, input: Value) -> anyhow::Result<Value> {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry.prepare_dispatch_input("threat-intel:apply", input, &ctx, None)?;
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }
}

#[test]
fn preview_cannot_complete_map_or_enter_supported_discovery() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("threat-intel:apply").unwrap();
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::InputAware);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable("threat-intel:apply"));
}

#[test]
fn default_preview_needs_no_runtime_and_live_dispatch_stays_explicit() {
    use crate::modules::runtime_requirements::{tool_execution_model, tool_needs_runtime};
    let config = V2Config::default();
    for input in [json!({}), json!({"dryRun":true})] {
        assert!(!tool_needs_runtime("threat-intel:apply", &input));
        assert_eq!(
            tool_execution_model("threat-intel:apply", &input, &config),
            None
        );
    }
    assert!(tool_needs_runtime(
        "threat-intel:apply",
        &json!({"dryRun":false})
    ));
}

#[test]
fn exact_default_preview_plans_metadata_without_creating_investigation_work() {
    let f = Fixture::new();
    let result = f.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["summary"]["dryRun"], true);
    assert_eq!(result["data"]["summary"]["totalEntries"], 2);
    assert_eq!(result["data"]["summary"]["planned"], 1);
    assert_eq!(result["data"]["summary"]["dispatchRequests"], 0);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("no hunts started"));
    let entries = result["data"]["entries"].as_array().unwrap();
    assert_eq!(entries[0]["status"], "planned");
    assert_eq!(entries[1]["status"], "skipped");
    assert!(entries[1]["reason"]
        .as_str()
        .unwrap()
        .contains("owned-inert"));
    assert!(!f.root.path().join(".kuzushi/v3/runs").exists());
    assert!(!f.root.path().join(".kuzushi/v3/index.sqlite3").exists());
}

#[test]
fn default_preview_reaches_catalog_errors_without_a_model_error() {
    let f = Fixture::new();
    let path = f.root.path().join(".kuzushi/catalogs/owned.toml");
    std::fs::write(&path, "invalid = [").unwrap();
    let error = f.dispatch(json!({})).unwrap_err();
    assert!(format!("{error:#}").contains("invalid TOML"), "{error:#}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "invalid = [");
}

#[test]
fn live_dispatch_missing_runtime_is_refused_before_any_child_work() {
    let f = Fixture::new();
    assert!(f.dispatch(json!({"dryRun":false})).is_err());
    assert!(!f.root.path().join(".kuzushi/v3/runs").exists());
}
