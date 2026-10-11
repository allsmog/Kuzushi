use super::*;
use serde_json::Value;

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("src")).unwrap();
        std::fs::write(
            root.path().join("src/owned.rs"),
            "// Inert policy fixture\n",
        )
        .unwrap();
        std::fs::write(root.path().join("README.md"), "Owned planning fixture\n").unwrap();
        Self {
            workspace: WorkspaceTarget::new(root.path()).unwrap(),
            root,
            config: V2Config {
                model: Some("openai-codex:gpt-5.5".into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn save(&self, expected: u32, text: &str) -> BriefRevision {
        save_brief(self.root.path(), "repository", expected, text, &|| false).unwrap()
    }

    fn scan_input(&self, kind: &str, brief: &BriefRevision) -> Value {
        let mut input = json!({"campaignId":"brief-plan","investigationId":"brief-accounting",
            "briefRef":brief.reference,"scanInput":{"taskMode":"manual","tasks":["secret-scan"]}});
        match kind {
            "scope" => {
                input["scopeProposalRef"] = self.scopes();
                input["scopeCases"] = json!([{"scopeId":"source"},{"scopeId":"docs"}]);
            }
            "matrix" => {
                input["baselineCaseId"] = json!("baseline");
                input["contextCases"] = self.context_cases();
            }
            "plain" => input["scanInput"]["threatModelRef"] = Value::Null,
            _ => panic!("Unknown owned fixture plan"),
        }
        input
    }

    fn scopes(&self) -> Value {
        use crate::workspace::{
            accept_scan_scope_proposal, create_scan_scope_proposal, ScopeCoverageApproval,
        };
        let draft = serde_json::from_value(json!({"schemaVersion":1,"sharedDiscovery":false,"exclusions":[],
            "scopes":[{"id":"source","name":"Source","paths":["src"],"rationale":"Owned source", "sharedDependencies":[],"openQuestions":[]},
                {"id":"docs","name":"Docs","paths":["README.md"],"rationale":"Loose root file", "sharedDependencies":[],"openQuestions":[]}]})).unwrap();
        let proposal = create_scan_scope_proposal(&self.context(), Some(draft)).unwrap();
        let accepted = accept_scan_scope_proposal(
            &self.context(),
            &proposal.reference,
            ScopeCoverageApproval {
                inventory_limitations: true,
                exclusions: false,
                overlapping_discovery: false,
            },
        )
        .unwrap();
        json!(accepted.reference)
    }

    fn context_cases(&self) -> Value {
        let cases = ["baseline", "candidate"].map(|label| {
            let output = self.registry.execute_tool("threat-model:import", json!({"activate":false,"label":label,
                "document":{"version":"1","methodology":"stride","title":label,"systemContext":"Owned planning fixture",
                "dfd":{"nodes":[{"id":"app","name":"Policy","type":"process","trustZone":"internal"}],
                    "flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}), &self.context()).unwrap();
            json!({"id":label,"label":label,"threatModelRef":output["data"]["modelRef"]})
        });
        json!(cases)
    }

    fn approve(&self, result: &Value) {
        let prepared = self.registry.prepare_dispatch_input("campaign:approve-allowance", json!({
            "campaignId":"brief-plan","investigationId":"brief-accounting","expectedRevision":0,
            "model":"openai-codex:gpt-5.5","campaignPlanSha256":result["data"]["planSha256"],
            "campaignJobs":result["data"]["jobCount"],"maxJobAttempts":1,
            "maxProviderCalls":11,"protectedReviewCalls":2,"reason":"Offline brief binding test; no jobs started"
        }), &self.context(), None).unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &self.context(), None)
            .unwrap();
    }

    fn export_result(&self) -> anyhow::Result<Value> {
        let prepared = self.registry.prepare_dispatch_input("workspace:export-findings", json!({
            "format":"json","output":".kuzushi/reports/brief.json","campaignId":"brief-plan","allowEmpty":true
        }), &self.context(), None).unwrap().authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &self.context(), None)
    }

    fn export(&self) -> (Value, Value) {
        let result = self.export_result().unwrap();
        let receipt =
            std::fs::read(result["data"]["investigationReceiptPath"].as_str().unwrap()).unwrap();
        let output = std::fs::read(self.root.path().join(".kuzushi/reports/brief.json")).unwrap();
        (
            serde_json::from_slice(&receipt).unwrap(),
            serde_json::from_slice(&output).unwrap(),
        )
    }
}

#[test]
fn all_discovery_plan_reports_keep_the_frozen_goal_after_head_changes() {
    for kind in ["plain", "scope", "matrix"] {
        let fixture = Fixture::new();
        let first = fixture.save(0, "Review package policy\nPreserve the baseline.");
        let result = fixture
            .registry
            .execute_tool(
                "campaign:study",
                fixture.scan_input(kind, &first),
                &fixture.context(),
            )
            .unwrap();
        fixture.approve(&result);
        let original = super::super::super::approved_work::read_bounded_plan(
            fixture.root.path(),
            "brief-plan",
        )
        .unwrap();
        fixture.save(1, "Later priorities must not rewrite approved history.");
        let (receipt, export) = fixture.export();
        assert_eq!(receipt["investigationBrief"], json!(first), "{kind}");
        assert_eq!(
            export["metadata"]["investigation"]["investigationBrief"],
            json!(first),
            "{kind}"
        );
        let document =
            crate::workspace::load_investigation_report_document(&fixture.workspace, "brief-plan")
                .unwrap();
        assert_eq!(document.summary().investigation_brief, Some(&first));
        assert_eq!(document.work_counts().completed, 0);
        assert_eq!(document.summary().observation_count, 0);
        assert_eq!(
            super::super::super::approved_work::read_bounded_plan(
                fixture.root.path(),
                "brief-plan"
            )
            .unwrap(),
            original
        );
        assert!(original["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|job| job["input"].get("briefRef").is_none()));
        assert!(!fixture
            .root
            .path()
            .join(".kuzushi/v3/campaigns/brief-plan/queue.json")
            .exists());
        assert!(
            crate::capabilities::threat_model::load_active_threat_model(fixture.root.path())
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn context_generation_plan_keeps_goal_out_of_model_input_and_active_context() {
    let fixture = Fixture::new();
    let first = fixture.save(0, "Ask the owner about package policy.");
    fixture.registry.execute_tool("campaign:context-study", json!({
        "campaignId":"brief-context","investigationId":"brief-accounting","briefRef":first.reference,"contextInput":{}
    }), &fixture.context()).unwrap();
    let plan =
        super::super::super::approved_work::read_bounded_plan(fixture.root.path(), "brief-context")
            .unwrap();
    let receipt =
        super::super::super::load_context_study(fixture.root.path(), "brief-context").unwrap();
    fixture.save(1, "Different priorities for later work.");
    assert_eq!(plan["investigationBrief"], json!(first));
    assert_eq!(
        load_plan_brief(fixture.root.path(), "brief-context").unwrap(),
        Some(first)
    );
    assert_eq!(plan["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(receipt.input["activate"], false);
    assert!(receipt.input.get("briefRef").is_none());
    assert!(receipt.input.get("investigationBrief").is_none());
    assert_eq!(
        super::super::super::load_context_study(fixture.root.path(), "brief-context").unwrap(),
        receipt
    );
    assert!(
        crate::capabilities::threat_model::load_active_threat_model(fixture.root.path())
            .unwrap()
            .is_none()
    );
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/brief-context/queue.json")
        .exists());
}

#[test]
fn missing_published_goal_refuses_report_without_replacing_existing_export() {
    let fixture = Fixture::new();
    let first = fixture.save(0, "Review policy.");
    let result = fixture
        .registry
        .execute_tool(
            "campaign:study",
            fixture.scan_input("plain", &first),
            &fixture.context(),
        )
        .unwrap();
    fixture.approve(&result);
    fixture.export();
    let output = fixture.root.path().join(".kuzushi/reports/brief.json");
    let previous = std::fs::read(&output).unwrap();
    std::fs::remove_file(
        fixture
            .root
            .path()
            .join(".kuzushi/v3/investigation-briefs/repository/revisions/1.json"),
    )
    .unwrap();
    assert!(
        crate::workspace::load_investigation_report_document(&fixture.workspace, "brief-plan")
            .is_err()
    );
    assert!(fixture.export_result().is_err());
    assert_eq!(std::fs::read(output).unwrap(), previous);
}
