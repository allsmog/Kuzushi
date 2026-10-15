use crate::capabilities::taint_iris_next::{
    load_taint_iris_next_target_catalog, run_taint_iris_next_sink_import_report,
    taint_iris_next_target_catalog_path,
};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::PathBuf;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    input: PathBuf,
}

impl Fixture {
    fn new(content: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let input = root.path().join("owned.jsonl");
        std::fs::write(&input, content).unwrap();
        Self {
            root,
            workspace,
            input,
        }
    }

    fn dispatch(&self, extra: Value) -> anyhow::Result<Value> {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let mut input = json!({"sinksPath":self.input});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input("taint-iris-next:import-sinks", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }

    fn saved_path(&self) -> PathBuf {
        taint_iris_next_target_catalog_path(self.root.path())
    }

    fn seed_malformed_catalog(&self) -> Vec<u8> {
        let bytes = b"Owned malformed metadata. Preserve until explicitly replaced.".to_vec();
        std::fs::create_dir_all(self.saved_path().parent().unwrap()).unwrap();
        std::fs::write(self.saved_path(), &bytes).unwrap();
        bytes
    }
}

#[test]
fn prepared_sink_import_round_trips_and_merges_without_discovery() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\",\"cwe\":\"CWE-20\"}\n");
    assert_eq!(fixture.dispatch(json!({})).unwrap()["status"], "completed");
    std::fs::write(
        &fixture.input,
        "{\"callee\":\"OwnedBeta\",\"cwe\":\"CWE-20\"}\n",
    )
    .unwrap();
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["data"]["mergedExisting"], true);
    let saved = load_taint_iris_next_target_catalog(fixture.root.path()).unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].sink_signals, vec!["OwnedAlpha(", "OwnedBeta("]);
    assert!(!fixture.root.path().join(".kuzushi/v3/campaigns").exists());
    assert!(!fixture.workspace.findings_db_path().exists());
}

#[test]
fn unusable_inventory_lines_are_partial_with_visible_warnings() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\ninvalid\n{}\n");
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["importedRows"], 1);
    assert_eq!(result["data"]["skippedLines"], 2);
    assert!(!result["warnings"].as_array().unwrap().is_empty());
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Complete import is not claimed"));
}

#[test]
fn default_merge_refuses_malformed_catalog_without_replacement() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\n");
    let prior = fixture.seed_malformed_catalog();
    let result = fixture.dispatch(json!({}));
    assert!(result.is_err(), "{result:?}");
    assert_eq!(std::fs::read(fixture.saved_path()).unwrap(), prior);
}

#[test]
fn explicit_replace_can_recover_an_unreadable_catalog() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\n");
    fixture.seed_malformed_catalog();
    let result = fixture.dispatch(json!({"merge":false})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["mergedExisting"], false);
    assert!(load_taint_iris_next_target_catalog(fixture.root.path()).is_some());
}

#[test]
fn metadata_import_cannot_own_a_scan_phase_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry
        .resolve_tool("taint-iris-next:import-sinks")
        .unwrap();
    assert!(!tool.phase_result);
    assert!(
        tool.options
            .iter()
            .find(|option| option.name == "sinksPath")
            .unwrap()
            .required
    );
}

#[test]
fn inventory_path_preserves_literal_trailing_space() {
    let mut fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\n");
    let next = fixture.root.path().join("owned inventory.jsonl ");
    std::fs::rename(&fixture.input, &next).unwrap();
    fixture.input = next;
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["data"]["sinksPath"],
        fixture
            .input
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
}

#[test]
fn precanceled_import_does_not_read_missing_input_or_publish() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\n");
    let config = V2Config::default();
    let cancel = crate::scan::ScanCancellation::default();
    cancel.cancel();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&fixture.workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancel),
        authorization: Default::default(),
    };
    let error =
        run_taint_iris_next_sink_import_report(&json!({"sinksPath":"missing owned input"}), &ctx)
            .unwrap_err();
    assert!(error.to_string().contains("canceled"), "{error:#}");
    assert!(!fixture.saved_path().exists());
}

#[cfg(unix)]
#[test]
fn symlinked_inventory_is_refused_without_changing_saved_metadata() {
    let fixture = Fixture::new("{\"callee\":\"OwnedAlpha\"}\n");
    let prior = fixture.seed_malformed_catalog();
    let linked = fixture.root.path().join("linked.jsonl");
    std::os::unix::fs::symlink(&fixture.input, &linked).unwrap();
    assert!(fixture.dispatch(json!({"sinksPath":linked})).is_err());
    assert_eq!(std::fs::read(fixture.saved_path()).unwrap(), prior);
}

#[test]
fn excessive_inventory_rows_are_refused_before_replacement() {
    let fixture = Fixture::new(&"{\"callee\":\"OwnedAlpha\"}\n".repeat(100_001));
    assert!(fixture.dispatch(json!({})).is_err());
    assert!(!fixture.saved_path().exists());
}
