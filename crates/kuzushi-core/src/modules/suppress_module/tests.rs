use crate::config::V2Config;
use crate::findings::{Finding, FindingStore, Severity};
use crate::modules::{
    FindingStoreRequirement, ModuleRegistry, RuntimeRequirement, ToolEffect, ToolExecutionContext,
    ToolPhase,
};
use crate::suppressions::{load_suppression_rules, save_suppression_rules};
use crate::WorkspaceTarget;
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

struct Fixture {
    _directory: TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    registry: ModuleRegistry,
    fingerprint: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(directory.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("owned", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "owned/note",
            "reader.rs",
            1,
            None,
            Severity::Info,
            "Labeled audit observation",
        );
        store.insert_finding("owned", &finding).unwrap();
        Self {
            _directory: directory,
            workspace,
            store,
            config: V2Config::default(),
            registry: ModuleRegistry::with_v2_builtins(),
            fingerprint: finding.fingerprint,
        }
    }

    fn context(&self, include_store: bool) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: include_store.then_some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn dispatch(&self, tool: &str, input: Value) -> anyhow::Result<Value> {
        let ctx = self.context(true);
        let prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }

    fn execute(&self, tool: &str, input: Value) -> Value {
        self.dispatch(tool, input).unwrap()
    }

    fn add(&self) -> Value {
        self.execute(
            "suppress:add",
            json!({
                "finding": self.fingerprint, "reason": "false-positive",
                "statement": "Owned labeled observation", "ruleId": "owned-rule",
            }),
        )
    }

    fn suppressed(&self) -> bool {
        self.store.list_all_findings().unwrap()[0].suppressed
    }
}

#[test]
fn suppression_contract_declares_reconciliation_and_required_store() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in ["suppress:add", "suppress:list", "suppress:remove"] {
        let descriptor = registry.resolve_tool(name).unwrap();
        assert_eq!(descriptor.phase, ToolPhase::Review, "{name}");
        assert_eq!(descriptor.effect, ToolEffect::WorkspaceWrite, "{name}");
        assert_eq!(
            descriptor.finding_store_requirement,
            FindingStoreRequirement::Required,
            "{name}"
        );
        assert_eq!(
            descriptor.runtime_requirement,
            RuntimeRequirement::Never,
            "{name}"
        );
        assert!(!descriptor.phase_result, "{name}");
    }
}

#[test]
fn shared_suppression_dispatch_rejects_missing_store_before_writing() {
    let fixture = Fixture::new();
    for (tool, input) in [
        (
            "suppress:add",
            json!({"rule": "owned/note", "reason": "false-positive", "statement": "owned"}),
        ),
        ("suppress:list", json!({})),
        ("suppress:remove", json!({"id": "owned-rule"})),
    ] {
        let ctx = fixture.context(false);
        let prepared = fixture
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        let error = fixture
            .registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("requires an active findings store"),
            "{error}"
        );
    }
    assert!(!fixture.workspace.suppressions_path().exists());
    assert!(!fixture.suppressed());
}

#[test]
fn suppression_list_cannot_reconcile_under_scan_posture() {
    let mut fixture = Fixture::new();
    fixture.add();
    let mut rules = load_suppression_rules(&fixture.workspace).unwrap();
    rules[0].expires_at_unix = Some(1);
    save_suppression_rules(&fixture.workspace, &rules).unwrap();
    fixture.config.autonomy = crate::modules::autonomy::AutonomyPosture::Scan;
    let error = fixture
        .dispatch("suppress:list", json!({}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("review action"), "{error}");
    assert!(fixture.suppressed());
}

#[test]
fn shared_suppression_add_list_remove_preserves_observation() {
    let fixture = Fixture::new();
    assert_eq!(fixture.add()["data"]["reconcile"]["added"], 1);
    assert!(fixture.suppressed());
    let findings = fixture.execute("findings:list", json!({}));
    assert_eq!(findings["data"]["findings"][0]["suppressed"], true);
    assert_eq!(
        findings["data"]["findings"][0]["review_decision"],
        Value::Null
    );
    let listed = fixture.execute("suppress:list", json!({}));
    assert_eq!(listed["data"]["activeCount"], 1);
    assert_eq!(listed["data"]["reconcile"]["added"], 0);
    let removed = fixture.execute("suppress:remove", json!({"rule_id": "owned-rule"}));
    assert_eq!(removed["data"]["reopened"], 1);
    assert!(!fixture.suppressed());
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 1);
    assert_eq!(
        fixture.execute("findings:list", json!({}))["data"]["count"],
        1
    );
}

#[test]
fn shared_suppression_list_reconciles_expiry_and_is_idempotent() {
    let fixture = Fixture::new();
    fixture.add();
    let mut rules = load_suppression_rules(&fixture.workspace).unwrap();
    rules[0].expires_at_unix = Some(1);
    save_suppression_rules(&fixture.workspace, &rules).unwrap();
    let listed = fixture.execute("suppress:list", json!({}));
    assert_eq!(listed["data"]["expiredRules"], json!(["owned-rule"]));
    assert_eq!(listed["data"]["reconcile"]["expired"], 1);
    assert!(!fixture.suppressed());
    assert_eq!(
        fixture.execute("suppress:list", json!({}))["data"]["reconcile"]["expired"],
        0
    );
}

#[test]
fn suppression_remove_aliases_are_canonical_and_missing_id_is_rejected() {
    let registry = ModuleRegistry::with_v2_builtins();
    for alias in ["id", "ruleId", "rule_id"] {
        let prepared = registry
            .prepare_tool_input("suppress:remove", json!({alias: "owned"}), None)
            .unwrap();
        assert_eq!(prepared["id"], "owned");
    }
    assert!(registry
        .prepare_tool_input("suppress:remove", json!({}), None)
        .is_err());
    assert!(registry
        .prepare_tool_input("suppress:list", json!({"unexpected": true}), None)
        .is_err());
}

#[test]
fn suppression_malformed_rules_do_not_reopen_findings() {
    let fixture = Fixture::new();
    fixture.add();
    std::fs::write(fixture.workspace.suppressions_path(), "broken = [").unwrap();
    let error = fixture.dispatch("suppress:list", json!({})).unwrap_err();
    assert!(error.to_string().contains("Could not parse"));
    assert!(fixture.suppressed());
}

#[test]
fn suppression_removal_preserves_independent_human_dismissal() {
    let fixture = Fixture::new();
    fixture.execute("findings:dismiss", json!({
        "finding": fixture.fingerprint, "reason": "false_positive", "note": "Human audit decision",
    }));
    fixture.add();
    fixture.execute("suppress:remove", json!({"id": "owned-rule"}));
    let rows = fixture.execute("findings:list", json!({}));
    assert_eq!(rows["data"]["count"], 1);
    assert_eq!(
        fixture.store.list_all_findings().unwrap()[0].fingerprint,
        fixture.fingerprint
    );
    let records = fixture
        .store
        .list_review_decisions_for_findings(&fixture.store.list_all_findings().unwrap())
        .unwrap();
    assert_eq!(records.len(), 1);
}
