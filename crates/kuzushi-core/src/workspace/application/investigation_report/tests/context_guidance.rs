//! Historical guidance is auxiliary and never reads the active context or goal.
use super::*;
use crate::{ToolExecutionContext, V2Config};

mod source_context;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("main.rs"),
            "// Owned inert reader fixture.\n",
        )
        .unwrap();
        Self {
            workspace: WorkspaceTarget::new(root.path()).unwrap(),
            root,
            config: V2Config::default(),
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn call(&self, name: &str, input: serde_json::Value) -> serde_json::Value {
        self.registry
            .execute_tool(name, input, &self.ctx())
            .unwrap()["data"]
            .clone()
    }

    fn goal(&self, previous: u32, text: &str) -> serde_json::Value {
        self.call(
            "campaign:brief",
            json!({"mode":"save","expectedRevision":previous,"text":text}),
        )["brief"]
            .clone()
    }

    fn imported_context(&self, goal: &serde_json::Value, title: &str) -> serde_json::Value {
        self.call("threat-model:import", json!({"activate":true,"label":title,
            "document":{"version":"1","methodology":"stride","title":title,
                "systemContext":"Labeled imported context. Model use is unverified.",
                "dfd":{"nodes":[{"id":"greeting","name":"Greeting","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},
                "provenance":{"operatorIntent":{"schemaVersion":1,"reference":goal["reference"],
                    "textBytes":goal["document"]["text"].as_str().unwrap().len(),
                    "purpose":"architecture priorities and open questions","sourceEvidence":false,"findingAuthority":false}}}}))["modelRef"].clone()
    }

    fn plan(&self, id: &str, contexts: Option<serde_json::Value>, reference: &serde_json::Value) {
        let mut input = json!({"campaignId":id,"investigationId":id,
            "scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":reference}});
        if let Some(cases) = contexts {
            input["contextCases"] = cases;
            input["baselineCaseId"] = json!("old");
            input["scanInput"]
                .as_object_mut()
                .unwrap()
                .remove("threatModelRef");
        }
        let plan = self.call("campaign:study", input);
        let approval = self.registry.prepare_dispatch_input("campaign:approve-allowance", json!({
            "campaignId":id,"investigationId":id,"expectedRevision":0,
            "campaignPlanSha256":plan["planSha256"],"campaignJobs":plan["jobCount"],"maxJobAttempts":1,
            "model":"openai-codex:gpt-5.5","maxProviderCalls":1,"protectedReviewCalls":1,
            "reason":"Offline report reading fixture. No jobs run."}), &self.ctx(), None).unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(approval, &self.ctx(), None)
            .unwrap();
    }

    fn export(&self, id: &str) -> serde_json::Value {
        let prepared = self
            .registry
            .prepare_dispatch_input(
                "workspace:export-findings",
                json!({"campaignId":id,"output":format!("{id}.json"),"allowEmpty":true}),
                &self.ctx(),
                None,
            )
            .unwrap()
            .authorize_explicit_headless();
        let result = self
            .registry
            .dispatch_prepared_input_with_runtime(prepared, &self.ctx(), None)
            .unwrap();
        serde_json::from_slice(
            &fs::read(result["data"]["investigationReceiptPath"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
    }

    fn manifest(&self) -> Vec<u8> {
        fs::read(
            self.root
                .path()
                .join(".kuzushi/threat-models/manifest.json"),
        )
        .unwrap()
    }
}

#[test]
fn exact_reader_and_export_keep_recorded_goal_after_active_context_and_goal_change() {
    let fixture = Fixture::new();
    let first = fixture.goal(0, "Original priorities\n東京 owner questions.");
    let selected = fixture.imported_context(&first, "Historical context");
    fixture.plan("goal-reader", None, &selected);
    let later = fixture.goal(1, "Later priorities must not be substituted");
    fixture.imported_context(&later, "Other active context");
    let before = fixture.manifest();
    let original = crate::capabilities::threat_model::load_exact_threat_model(
        fixture.root.path(),
        &serde_json::from_value(selected.clone()).unwrap(),
    )
    .unwrap();
    let read = fixture.call("threat-model:read", json!({"threatModelRef":selected}));
    assert_eq!(read["document"], original);
    assert_eq!(read["goalState"]["text"], first["document"]["text"]);
    assert_eq!(read["goalState"]["modelUseVerified"], false);
    let exported = fixture.export("goal-reader");
    let guidance = &exported["scope"]["contextGuidance"];
    assert_eq!(guidance["contextRef"], selected);
    assert_eq!(guidance["reference"], first["reference"]);
    assert_eq!(guidance["text"], first["document"]["text"]);
    assert_eq!(guidance["referenceAuthenticated"], true);
    assert_eq!(guidance["modelUseVerified"], false);
    assert_eq!(exported["occurrence"]["pending"], 3);
    assert_eq!(fixture.manifest(), before);
}

#[test]
fn missing_goal_does_not_destroy_report_or_substitute_current_head() {
    let fixture = Fixture::new();
    let first = fixture.goal(0, "Old goal");
    let selected = fixture.imported_context(&first, "Old context");
    fixture.plan("missing-guidance", None, &selected);
    fixture.goal(1, "Current goal must remain separate");
    fs::remove_file(
        fixture
            .root
            .path()
            .join(".kuzushi/v3/investigation-briefs/repository/revisions/1.json"),
    )
    .unwrap();
    let before = fixture.manifest();
    let read = fixture.call("threat-model:read", json!({"threatModelRef":selected}));
    assert_eq!(read["goalState"]["status"], "unavailable");
    assert_eq!(read["document"]["title"], "Old context");
    let exported = fixture.export("missing-guidance");
    assert_eq!(
        exported["scope"]["contextGuidance"]["status"],
        "unavailable"
    );
    assert!(exported["scope"]["contextGuidance"].get("text").is_none());
    assert_eq!(exported["occurrence"]["pending"], 3);
    assert_eq!(fixture.manifest(), before);
}

#[test]
fn matrix_report_preserves_each_cases_distinct_goal_and_explicit_omission() {
    let fixture = Fixture::new();
    let first = fixture.goal(0, "Baseline goal");
    let old = fixture.imported_context(&first, "Baseline context");
    let second = fixture.goal(1, "Experiment goal");
    let changed = fixture.imported_context(&second, "Experiment context");
    fixture.plan(
        "guidance-matrix",
        Some(json!([
            {"id":"old","label":"Baseline","threatModelRef":old},
            {"id":"changed","label":"Experiment","threatModelRef":changed},
            {"id":"omitted","label":"No context","threatModelRef":null}
        ])),
        &serde_json::Value::Null,
    );
    fixture.goal(2, "Current head must not replace either case");
    let exported = fixture.export("guidance-matrix");
    let cases = &exported["scope"]["caseContextGuidance"];
    assert_eq!(cases["old"]["text"], "Baseline goal");
    assert_eq!(cases["changed"]["text"], "Experiment goal");
    assert_eq!(cases["old"]["contextRef"], old);
    assert_eq!(cases["changed"]["contextRef"], changed);
    assert_eq!(cases["omitted"]["status"], "omitted");
    assert!(cases["omitted"].get("text").is_none());
    assert_eq!(
        exported["occurrence"]["cases"][0]["occurrence"]["pending"],
        3
    );
}

#[test]
fn legacy_and_omitted_inputs_never_inspect_active_context() {
    let fixture = Fixture::new();
    let goal = fixture.goal(0, "Active context priorities");
    fixture.imported_context(&goal, "Current context");
    let before = fixture.manifest();
    for (input, status) in [
        (json!({}), "unbound"),
        (json!({"threatModelRef":null}), "omitted"),
        (json!({"threatModelRef":"active"}), "unavailable"),
    ] {
        let state =
            super::super::scope::recorded_context_report(&fixture.workspace, &input).guidance;
        assert_eq!(state["status"], status);
        assert!(state.get("text").is_none());
    }
    assert_eq!(fixture.manifest(), before);
}
