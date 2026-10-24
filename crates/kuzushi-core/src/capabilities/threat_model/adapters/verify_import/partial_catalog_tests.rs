use super::*;
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};

fn document() -> Value {
    json!({"version":"1","methodology":"stride","title":"Owned partial context fixture",
        "systemContext":"An owned inert source fixture. Oversized material is not fully inspected.",
        "dfd":{"nodes":[{"id":"app","name":"Owned source","type":"process","trustZone":"local"}],
            "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}})
}

fn source_document(root: &Path) -> Value {
    let catalog = crate::capabilities::entry_points::ensure_observed_entry_point_catalog(root)
        .unwrap()
        .catalog
        .unwrap();
    assert_eq!(catalog.total, 1);
    let mut value = document();
    value["deprioritized"] = json!([{"entryPointId":catalog.entry_points[0].surface.id,
        "reason":"The owned app.py contains static comments only; this filename-derived entry point needs source review, not a runtime or vulnerability claim."}]);
    value
}

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

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, crate::ThreatModelRef) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("app.py"), "# Owned inert source fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let parent = registry
        .execute_tool("threat-model:import", json!({"document":document()}), &ctx)
        .unwrap();
    let parent = serde_json::from_value(parent["data"]["modelRef"].clone()).unwrap();
    std::fs::write(temp.path().join("oversized.txt"), vec![b'a'; 262_145]).unwrap();
    let snapshot = registry
        .execute_tool("context:build", json!({"enrichment":false}), &ctx)
        .unwrap();
    assert_eq!(snapshot["status"], "partial");
    (temp, workspace, parent)
}

fn assert_partial_verification(verification: &Value) {
    assert_eq!(verification["verdict"], "partial");
    assert_eq!(verification["coverageConsidered"], 1);
    assert_eq!(verification["coverageGaps"], 0);
    assert_eq!(verification["groundingSource"], "partial-catalog");
    assert!(verification["groundingDegraded"]
        .as_str()
        .unwrap()
        .contains("per-file inspection cap"));
}

#[test]
fn inactive_import_retains_partial_coverage_and_preserves_the_active_revision() {
    let (_root, workspace, parent) = fixture();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry
        .execute_tool(
            "threat-model:import",
            json!({"document":source_document(workspace.root()),"activate":false}),
            &ctx,
        )
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_partial_verification(&result["data"]["verification"]);
    assert_eq!(
        load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref,
        parent
    );
    let reference = serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let exact = load_exact_threat_model(workspace.root(), &reference).unwrap();
    assert_eq!(exact["verification"]["verdict"], "partial");
    let warning = verification_warning(&exact, workspace.root()).unwrap();
    assert!(warning.contains("partial") && warning.contains("unknown"));
    let strict =
        crate::capabilities::entry_points::ensure_current_entry_point_catalog(workspace.root());
    assert!(strict
        .unwrap_err()
        .to_string()
        .contains("requires a complete context snapshot"));
}

#[test]
fn partial_import_refuses_implicit_activation_without_replacing_the_active_context() {
    let (_root, workspace, parent) = fixture();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry.execute_tool(
        "threat-model:import",
        json!({"document":document()}),
        &context(&workspace, &config),
    );
    assert!(result.unwrap_err().to_string().contains("activate=false"));
    assert_eq!(
        load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref,
        parent
    );
}

#[test]
fn partial_coverage_does_not_hide_missing_source_evidence() {
    let (_root, workspace, _parent) = fixture();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let imported = registry
        .execute_tool(
            "threat-model:import",
            json!({"document":document(),"activate":false}),
            &context(&workspace, &config),
        )
        .unwrap();
    let mut value = imported["data"]["document"].clone();
    value["evidence"] = json!({"filePath":"missing.py","startLine":1});
    let verification = verify_threat_model_document(&value, workspace.root()).unwrap();
    assert_eq!(verification.verdict, "failed");
    assert_eq!(verification.missing_count, 1);
    assert_eq!(verification.grounding_source, "partial-catalog");
    stamp_verification(&mut value, &verification);
    assert!(verification_warning(&value, workspace.root())
        .unwrap()
        .contains("verification failed"));
}

#[test]
fn partial_catalog_rows_still_require_explicit_disposition() {
    let (_root, workspace, _parent) = fixture();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry
        .execute_tool(
            "threat-model:import",
            json!({"document":document(),"activate":false}),
            &context(&workspace, &config),
        )
        .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["verification"]["verdict"], "failed");
    assert_eq!(result["data"]["verification"]["coverageGaps"], 1);
}

#[test]
fn partial_catalog_does_not_authenticate_a_complete_catalog_receipt() {
    let (_root, workspace, parent) = fixture();
    let catalog =
        crate::capabilities::entry_points::ensure_observed_entry_point_catalog(workspace.root())
            .unwrap()
            .catalog
            .unwrap();
    let mut value = source_document(workspace.root());
    value["provenance"] = json!({"entryPointCatalog":{
        "status":"current","sha256":catalog.provenance.sha256,
        "snapshotTimestamp":catalog.snapshot_timestamp,"contextSha256":catalog.provenance.context_snapshot_sha256,
        "treeHash":catalog.provenance.context_snapshot_tree_hash,
        "selectionPolicy":crate::capabilities::entry_points::ENTRY_POINT_SELECTION_POLICY}});
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry.execute_tool(
        "threat-model:import",
        json!({"document":value,"activate":false}),
        &context(&workspace, &config),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Complete-catalog receipts"));
    assert_eq!(
        load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref,
        parent
    );
}

#[test]
fn malformed_context_snapshot_does_not_become_a_partial_import() {
    let (_root, workspace, parent) = fixture();
    let snapshot = crate::context::context_snapshot_path(workspace.root());
    std::fs::write(&snapshot, "not a context snapshot").unwrap();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    assert!(registry
        .execute_tool(
            "threat-model:import",
            json!({"document":document(),"activate":false}),
            &context(&workspace, &config)
        )
        .is_err());
    assert_eq!(
        load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref,
        parent
    );
    assert_eq!(
        std::fs::read_to_string(snapshot).unwrap(),
        "not a context snapshot"
    );
}

#[test]
fn report_reads_selected_partial_context_without_substituting_the_active_revision() {
    let (_root, workspace, parent) = fixture();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let result = registry
        .execute_tool(
            "threat-model:import",
            json!({"document":source_document(workspace.root()),"activate":false}),
            &context(&workspace, &config),
        )
        .unwrap();
    let reference = result["data"]["modelRef"].clone();
    crate::capabilities::campaign::compile_scan_batch_plan(crate::capabilities::campaign::ScanBatchPlanSpec {
        root:workspace.root(),batch_id:Some("partial-context-report".into()),trials:3,requested_workers:1,
        gate_policy:Default::default(),prepared_input:json!({"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":reference}),
        config:&config,registry:&registry }).unwrap();
    let report =
        crate::workspace::load_investigation_report(&workspace, "partial-context-report").unwrap();
    let evidence = &report.scope["contextEvidence"];
    assert_eq!(evidence["contextRef"], reference);
    assert_eq!(evidence["verification"], result["data"]["verification"]);
    assert_eq!(
        evidence["verification"]["groundingSource"],
        "partial-catalog"
    );
    assert!(evidence["verification"]["groundingDegraded"]
        .as_str()
        .unwrap()
        .contains("262144"));
    assert_eq!(report.occurrence.pending, 3);
    assert_eq!(
        load_active_threat_model(workspace.root())
            .unwrap()
            .unwrap()
            .model_ref,
        parent
    );
}
