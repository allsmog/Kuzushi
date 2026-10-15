//! Real source-to-artifact consumers, without source execution or provider calls.
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::Path;

const SOURCE: &str = "# Labeled static fixture. Never executed.\nfrom flask import Flask\nfrom fastapi import FastAPI\nweb = Flask(__name__)\napi = FastAPI()\n@web.get('/health')\ndef health(): pass\n@api.post('/notes')\ndef notes(): pass\n";

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("app.py"), SOURCE).unwrap();
    root
}

fn dispatch(root: &Path, tool: &str, input: Value) -> anyhow::Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn read_snapshot(root: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(kuzushi_core::context::context_snapshot_path(root)).unwrap(),
    )
    .unwrap()
}

fn assert_route(rows: &[Value], route: &str, framework: &str) {
    let row = rows.iter().find(|row| row["route"] == route).unwrap();
    assert_eq!(row["framework"], framework);
    assert!(row["line"].as_u64().unwrap() > 0);
    assert!(row["id"].as_str().unwrap().starts_with("AS-"));
    assert_eq!(row["metadata"]["sourcePolicy"], "python-http-receivers-v1");
}

#[test]
fn real_context_and_catalogue_preserve_nonempty_source_bound_routes() {
    let root = fixture();
    let before = std::fs::read(root.path().join("app.py")).unwrap();
    let context = dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    assert_eq!(context["status"], "completed");
    let snapshot = read_snapshot(root.path());
    assert!(kuzushi_core::context::context_snapshot_freshness(root.path(), &snapshot).is_current());
    let surfaces = snapshot["attackSurfaceMap"]["surfaces"].as_array().unwrap();
    assert_route(surfaces, "/health", "Flask");
    assert_route(surfaces, "/notes", "FastAPI");
    let entries = dispatch(root.path(), "entry-points:extract", json!({})).unwrap();
    let rows = entries["data"]["entryPoints"].as_array().unwrap();
    assert_route(rows, "/health", "Flask");
    assert_route(rows, "/notes", "FastAPI");
    assert_eq!(std::fs::read(root.path().join("app.py")).unwrap(), before);
}

#[test]
fn unresolved_receiver_keeps_the_route_and_omits_a_framework_claim() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("app.py"),
        "@app.get('/health')\ndef health(): pass\n",
    )
    .unwrap();
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    let result = dispatch(root.path(), "entry-points:extract", json!({})).unwrap();
    let rows = result["data"]["entryPoints"].as_array().unwrap();
    let row = rows.iter().find(|row| row["route"] == "/health").unwrap();
    assert!(row.get("framework").is_none_or(Value::is_null));
    assert_eq!(row["method"], "GET");
}

#[test]
fn source_drift_blocks_new_catalogue_output_and_preserves_prior_evidence() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    dispatch(root.path(), "entry-points:extract", json!({})).unwrap();
    let catalog = root.path().join(".kuzushi/entry-points.json");
    let before = std::fs::read(&catalog).unwrap();
    std::fs::write(
        root.path().join("app.py"),
        SOURCE.replace("/health", "/status"),
    )
    .unwrap();
    let error = dispatch(root.path(), "entry-points:extract", json!({})).unwrap_err();
    assert!(error.to_string().contains("stale"), "{error:#}");
    assert_eq!(std::fs::read(catalog).unwrap(), before);
}

#[test]
fn missing_context_has_a_concrete_prerequisite_and_no_catalogue() {
    let root = fixture();
    let error = dispatch(root.path(), "entry-points:extract", json!({})).unwrap_err();
    assert!(error.to_string().contains("context:build"));
    assert!(!root.path().join(".kuzushi/entry-points.json").exists());
}

#[test]
fn prepared_cancellation_preserves_catalog_and_source_bytes() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    dispatch(root.path(), "entry-points:extract", json!({})).unwrap();
    let catalog = root.path().join(".kuzushi/entry-points.json");
    let before = std::fs::read(&catalog).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let cancellation = kuzushi_core::scan::ScanCancellation::default();
    cancellation.cancel();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("entry-points:extract", json!({}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancel"), "{error:#}");
    assert_eq!(std::fs::read(catalog).unwrap(), before);
    assert_eq!(
        std::fs::read_to_string(root.path().join("app.py")).unwrap(),
        SOURCE
    );
}

#[test]
fn legacy_python_snapshot_is_not_reused_or_silently_repaired() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    let mut snapshot = read_snapshot(root.path());
    let row = snapshot["attackSurfaceMap"]["surfaces"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["route"] == "/health")
        .unwrap();
    row["framework"] = json!("FastAPI");
    row["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("sourcePolicy");
    let path = kuzushi_core::context::context_snapshot_path(root.path());
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        !kuzushi_core::context::context_snapshot_freshness(root.path(), &snapshot).is_current()
    );
    let error = dispatch(root.path(), "entry-points:extract", json!({})).unwrap_err();
    assert!(
        error.to_string().contains("framework extraction policy"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn deterministic_map_consumes_the_actual_catalogue_and_remains_explicitly_partial() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    let catalog = dispatch(root.path(), "entry-points:extract", json!({})).unwrap();
    let built = dispatch(
        root.path(),
        "threat-model:build",
        json!({"pipeline":"deterministic","offline":true,"variantScan":false}),
    )
    .unwrap();
    assert_eq!(built["status"], "partial");
    let document = &built["data"]["document"];
    assert!(!document["dfd"]["nodes"].as_array().unwrap().is_empty());
    assert!(!document["dfd"]["flows"].as_array().unwrap().is_empty());
    let entries = document["attackSurface"]["entryPoints"].as_array().unwrap();
    let extracted = catalog["data"]["entryPoints"].as_array().unwrap();
    for entry in entries {
        assert!(extracted
            .iter()
            .any(|row| row["id"] == entry["id"] && row["framework"] == entry["framework"]));
        assert!(!entry["targetElementIds"].as_array().unwrap().is_empty());
    }
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":built["data"]["modelRef"]}),
    )
    .unwrap();
    assert_eq!(read["data"]["document"], *document);
}
