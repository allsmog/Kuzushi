use crate::modules::{ModuleMaturity, RuntimeRequirement, ToolPhase};
use crate::{
    Finding, FindingStore, ModuleRegistry, Severity, ToolExecutionContext, V2Config,
    WorkspaceTarget,
};
use serde_json::{json, Value};

#[test]
fn advisory_chains_are_experimental_and_cannot_publish_review_progress() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("findings:chains").unwrap();
    assert_eq!(tool.phase, ToolPhase::Review);
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
    assert!(!tool.phase_result);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!registry.tool_is_discoverable("findings:chains"));
}

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        seed_metadata_ledger(&store, root.path());
        Self {
            root,
            workspace,
            store,
        }
    }

    fn dispatch(
        &self,
        input: Value,
        cancellation: Option<&crate::scan::ScanCancellation>,
    ) -> anyhow::Result<Value> {
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input("findings:chains", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }
}

fn seed_metadata_ledger(store: &FindingStore, root: &std::path::Path) {
    store
        .record_run_started("owned-ledger", root, "metadata")
        .unwrap();
    for (index, (title, confirmed)) in [
        ("Owned request metadata", true),
        ("Owned command metadata", true),
        ("Owned request remains unreviewed", false),
    ]
    .into_iter()
    .enumerate()
    {
        let finding = Finding::new_tool(
            "owned-ledger",
            &format!("owned-metadata-{index}"),
            "src/owned.rs",
            index as u32 + 1,
            None,
            Severity::Info,
            title,
        );
        let id = store.insert_finding("owned-ledger", &finding).unwrap();
        if confirmed {
            store
                .append_user_review_decision(id, &metadata_decision())
                .unwrap();
        }
    }
    store
        .record_run_finished("owned-ledger", "completed", 3)
        .unwrap();
}

fn metadata_decision() -> crate::findings::ReviewDecision {
    crate::findings::ReviewDecision {
        verdict: crate::findings::ReviewDecisionVerdict::Confirmed,
        author: crate::findings::TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Labeled inert metadata fixture, not a vulnerability verdict".into(),
        dismiss_reason: None,
        actor: Some("operator-fixture".into()),
    }
}

#[test]
#[ignore = "Explicit owned metadata export for the native journey"]
fn export_owned_chains_ledger_fixture() {
    let root = std::path::PathBuf::from(
        std::env::var("KUZUSHI_CHAIN_FIXTURE_TARGET").expect("owned fixture path required"),
    );
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    seed_metadata_ledger(&store, &root);
}

#[test]
fn exact_advisory_dispatch_persists_members_but_changes_no_findings_or_decisions() {
    let f = Fixture::new();
    let before = f.store.list_all_findings().unwrap().len();
    let result = f.dispatch(json!({"max_chains":1}), None).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["confirmedCount"], 2);
    assert_eq!(result["data"]["chains"].as_array().unwrap().len(), 1);
    let saved: Value = serde_json::from_slice(
        &std::fs::read(f.root.path().join(".kuzushi/v3/reports/chains.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(saved, result["data"]);
    assert_eq!(f.store.list_all_findings().unwrap().len(), before);
    let scene = crate::capabilities::try_load_persistent_exploit_chains(f.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(scene["chains"].as_array().unwrap().len(), 1);
    assert_eq!(scene["chains"][0]["steps"].as_array().unwrap().len(), 2);
}

#[test]
fn precanceled_advisory_read_preserves_existing_report() {
    let f = Fixture::new();
    f.dispatch(json!({}), None).unwrap();
    let path = f.root.path().join(".kuzushi/v3/reports/chains.json");
    let original = std::fs::read(&path).unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let error = f.dispatch(json!({}), Some(&cancellation)).unwrap_err();
    assert!(error.to_string().contains("cancel"), "{error:#}");
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn invalid_output_and_chain_limit_preserve_the_previous_artifact() {
    let f = Fixture::new();
    f.dispatch(json!({}), None).unwrap();
    let path = f.root.path().join(".kuzushi/v3/reports/chains.json");
    let original = std::fs::read(&path).unwrap();
    for input in [
        json!({"maxChains":0}),
        json!({"output":"../owned-outside.json"}),
        json!({"unknownField":true}),
    ] {
        assert!(f.dispatch(input, None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn missing_workspace_or_ledger_is_an_explicit_dispatch_error() {
    let f = Fixture::new();
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins();
    for (workspace, findings_store, expected) in [
        (None, Some(&f.store), "active workspace"),
        (Some(&f.workspace), None, "active findings store"),
    ] {
        let ctx = ToolExecutionContext {
            config: &config,
            workspace,
            findings_store,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let error = registry
            .prepare_dispatch_input("findings:chains", json!({}), &ctx, None)
            .and_then(|prepared| {
                registry.dispatch_prepared_input_with_runtime(
                    prepared.authorize_explicit_headless(),
                    &ctx,
                    None,
                )
            })
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
    assert!(!f
        .root
        .path()
        .join(".kuzushi/v3/reports/chains.json")
        .exists());
}
