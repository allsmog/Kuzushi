//! Scripted source-only generation over authenticated partial observations.
use super::super::*;
use super::tests::MockThreatRuntime;
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};

struct Fixture {
    _root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    parent: ThreatModelRef,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("app.py"), "# Owned inert source fixture\n").unwrap();
        fs::write(root.path().join("oversized.txt"), vec![b'a'; 262_145]).unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let config = V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        };
        let result = ModuleRegistry::with_v2_builtins_without_optional_adapters()
            .execute_tool(
                "threat-model:import",
                json!({"document":document()}),
                &context(&workspace, &config),
            )
            .unwrap();
        let fixture = Self {
            _root: root,
            workspace,
            config,
            parent: serde_json::from_value(result["data"]["modelRef"].clone()).unwrap(),
        };
        fixture.prepare_partial_snapshot();
        fixture
    }

    fn prepare_partial_snapshot(&self) {
        fs::write(
            self.workspace.root().join("oversized.txt"),
            vec![b'a'; 262_145],
        )
        .unwrap();
        let snapshot = self
            .registry()
            .execute_tool(
                "context:build",
                json!({"enrichment":false}),
                &self.context(),
            )
            .unwrap();
        assert_eq!(snapshot["status"], "partial");
    }

    fn registry(&self) -> ModuleRegistry {
        ModuleRegistry::with_v2_builtins_without_optional_adapters()
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        context(&self.workspace, &self.config)
    }

    fn document(&self) -> Value {
        let catalog = crate::capabilities::entry_points::ensure_observed_entry_point_catalog(
            self.workspace.root(),
        )
        .unwrap()
        .catalog
        .unwrap();
        assert_eq!(catalog.total, 1);
        let mut value = document();
        value["deprioritized"] = json!([{"entryPointId":catalog.entry_points[0].surface.id,
            "reason":"Owned static comments only. This filename-derived surface has no runtime or vulnerability claim."}]);
        value
    }

    fn build(&self, input: Value, runtime: &MockThreatRuntime) -> Result<Value> {
        let ctx = self.context();
        self.registry().execute_tool_with_runtime(
            "threat-model:build",
            input,
            &ctx,
            Some(&runtime.accounted(&ctx)),
        )
    }

    fn assert_parent_unchanged(&self) {
        assert_eq!(
            load_active_threat_model(self.workspace.root())
                .unwrap()
                .unwrap()
                .model_ref,
            self.parent
        );
    }
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

fn document() -> Value {
    json!({"version":"1","methodology":"stride","title":"Labeled scripted partial context",
        "systemContext":"Owned inert app.py contains static comments. Oversized material has only bounded inspection.",
        "dfd":{"nodes":[{"id":"app","name":"Owned source","type":"data-store","trustZone":"local",
            "description":"app.py contains owned static comments.","purpose":"Supplies source text for a bounded context regression.","sourceRefs":["app.py:1"]},
            {"id":"oversized","name":"Partly inspected text","type":"data-store","trustZone":"local",
                "description":"oversized.txt exceeds the bounded content inspection limit.","purpose":"Records source material not fully represented in this draft.","sourceRefs":["oversized.txt:1"]}],
            "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}})
}

fn input() -> Value {
    json!({"pipeline":"single","seedMode":"fresh","newModel":true,
        "activate":false,"sources":["entry-points","source-code"]})
}

#[test]
fn inactive_generation_uses_one_accounted_query_and_preserves_partial_grounding() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let result = fixture.build(input(), &runtime).unwrap();
    assert_eq!(runtime.requests().len(), 1);
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["modelRef"].is_object());
    let doc = &result["data"]["document"];
    assert_eq!(doc["provenance"]["entryPointCatalog"]["status"], "partial");
    assert_eq!(doc["verification"]["verdict"], "partial");
    assert_eq!(doc["verification"]["groundingSource"], "partial-catalog");
    let prompt = &runtime.requests()[0].prompt;
    assert!(prompt.contains("snapshotCoverage") && prompt.contains("262144"));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("unseen entry points remain unknown"));
    fixture.assert_parent_unchanged();
    assert!(
        crate::capabilities::entry_points::ensure_current_entry_point_catalog(
            fixture.workspace.root()
        )
        .is_err()
    );
}

#[test]
fn partial_generation_refuses_implicit_activation_before_any_query() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let mut selected = input();
    selected.as_object_mut().unwrap().remove("activate");
    let error = fixture.build(selected, &runtime).unwrap_err();
    assert!(error.to_string().contains("activate=false"), "{error:#}");
    assert!(runtime.requests().is_empty());
    fixture.assert_parent_unchanged();
}

#[test]
fn partial_receipt_rejects_a_changed_catalog_digest() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let result = fixture.build(input(), &runtime).unwrap();
    let mut document = result["data"]["document"].clone();
    document["provenance"]["entryPointCatalog"]["sha256"] = json!("sha256:changed");
    let error = verify_threat_model_document(&document, fixture.workspace.root()).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match the threat-model receipt"));
    assert_eq!(runtime.requests().len(), 1);
    fixture.assert_parent_unchanged();
}

#[test]
fn later_complete_catalog_does_not_promote_a_partial_receipt() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let result = fixture.build(input(), &runtime).unwrap();
    fs::remove_file(fixture.workspace.root().join("oversized.txt")).unwrap();
    let snapshot = fixture
        .registry()
        .execute_tool(
            "context:build",
            json!({"enrichment":false}),
            &fixture.context(),
        )
        .unwrap();
    assert_eq!(snapshot["status"], "completed");
    let error = verify_threat_model_document(&result["data"]["document"], fixture.workspace.root())
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("Partial-catalog receipts require"));
    assert_eq!(runtime.requests().len(), 1);
    fixture.assert_parent_unchanged();
}

#[test]
fn partial_receipt_cannot_outlive_its_authenticated_context_snapshot() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let result = fixture.build(input(), &runtime).unwrap();
    fs::remove_file(crate::context::context_snapshot_path(
        fixture.workspace.root(),
    ))
    .unwrap();
    assert!(
        verify_threat_model_document(&result["data"]["document"], fixture.workspace.root())
            .is_err()
    );
    assert_eq!(runtime.requests().len(), 1);
    fixture.assert_parent_unchanged();
}

#[test]
fn context_study_defaults_supply_the_recorded_partial_catalog_limit() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let mut selected = input();
    selected["sources"] = json!(["source-code"]);
    let result = fixture.build(selected, &runtime).unwrap();
    assert_eq!(runtime.requests().len(), 1);
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["modelRef"].is_object());
    assert!(runtime.requests()[0]
        .prompt
        .contains("per-file inspection cap of 262144"));
    fixture.assert_parent_unchanged();
}

#[test]
fn staged_generation_retains_partial_grounding_with_one_query() {
    let fixture = Fixture::new();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let mut selected = input();
    selected["pipeline"] = json!("staged");
    let result = fixture.build(selected, &runtime).unwrap();
    assert_eq!(runtime.requests().len(), 1);
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["modelRef"].is_object());
    assert_eq!(
        result["data"]["document"]["verification"]["verdict"],
        "partial"
    );
    fixture.assert_parent_unchanged();
}

#[test]
fn unchanged_partial_refine_needs_no_query_and_never_becomes_complete() {
    let fixture = Fixture::new();
    let initial = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let built = fixture.build(input(), &initial).unwrap();
    let runtime = MockThreatRuntime::new(json!({"document":fixture.document()}));
    let mut selected = input();
    selected["mode"] = json!("refine");
    selected["newModel"] = json!(false);
    selected["modelId"] = built["data"]["modelRef"]["modelId"].clone();
    selected.as_object_mut().unwrap().remove("seedMode");
    let refined = fixture.build(selected, &runtime).unwrap();
    assert!(runtime.requests().is_empty());
    assert_eq!(refined["status"], "partial");
    assert_eq!(
        refined["data"]["document"]["verification"]["verdict"],
        "partial"
    );
    fixture.assert_parent_unchanged();
}
