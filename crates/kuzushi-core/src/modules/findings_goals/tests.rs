use super::*;
use crate::findings::{Finding, Severity};

struct Fixture {
    _root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: crate::V2Config,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("note.txt"), "Owned inert policy text\n").unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        for (run, rule) in [("goals-a", "a"), ("goals-b", "b")] {
            store
                .with_run_lifecycle(run, workspace.root(), || {
                    store.insert_finding(
                        run,
                        &Finding::new_tool(
                            "owned-fixture",
                            rule,
                            "note.txt",
                            1,
                            None,
                            Severity::Info,
                            "Owned policy observation",
                        ),
                    )?;
                    Ok(((), 1))
                })
                .unwrap();
        }
        Self {
            _root: root,
            workspace,
            store,
            config: crate::V2Config::default(),
        }
    }

    fn call(&self, name: &str, input: Value) -> Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let prepared = registry.prepare_dispatch_input(name, input, &ctx, None)?;
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
    }

    fn brief(&self, expected: u32) -> Value {
        self.call("campaign:brief", json!({"mode":"save","expectedRevision":expected,"text":format!("Review owner policy, revision {}", expected+1)})).unwrap()["data"]["brief"]["reference"].clone()
    }

    fn page(&self, brief: &Value) -> Value {
        self.call("findings:goals", json!({"briefRef":brief}))
            .unwrap()["data"]
            .clone()
    }

    fn assessment(&self, brief: &Value, row: &Value, relevance: &str, expected: u64) -> Value {
        json!({"briefRef":brief,"basis":row["basis"],"relevance":relevance,"reason":"Reviewed owner policy, independently of validity","expectedRevision":expected})
    }
}

#[test]
fn goal_relevance_is_reversible_brief_bound_and_changes_no_finding_truth() {
    let f = Fixture::new();
    assert!(f.call("findings:goals", json!({})).unwrap()["data"]["brief"].is_null());
    let brief = f.brief(0);
    let original = f.store.list_all_findings().unwrap();
    let page = f.page(&brief);
    let chosen = &page["rows"][1];
    let input = f.assessment(&brief, chosen, "direct", 0);
    let record = f.call("findings:goal-assess", input.clone()).unwrap()["data"].clone();
    assert_eq!(record["revision"], 1);
    assert!(f.call("findings:goal-assess", input).is_err());
    let assessed = f.page(&brief);
    assert_eq!(assessed["rows"][0]["basis"], chosen["basis"]);
    assert_eq!(assessed["rows"][0]["assessment"]["relevance"], "direct");
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, chosen, "cleared", 1),
    )
    .unwrap();
    let current = f.page(&brief);
    let typed: crate::findings::FindingGoalPage = serde_json::from_value(current).unwrap();
    assert!(typed.rows.iter().all(|row| row.relevance().is_none()));
    let id = chosen["basis"]["findingId"].as_i64().unwrap();
    let reopened = FindingStore::open_read_only(f.workspace.findings_db_path()).unwrap();
    assert_eq!(reopened.finding_goal_history(id).unwrap().len(), 2);
    let next = f.brief(1);
    assert!(f.page(&next)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["assessment"].is_null()));
    assert_eq!(f.store.list_all_findings().unwrap(), original);
    assert!(f.store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn goal_review_rejects_forged_receipts_invalid_reasons_and_unknown_options() {
    let f = Fixture::new();
    let brief = f.brief(0);
    let page = f.page(&brief);
    let valid = f.assessment(&brief, &page["rows"][0], "outside", 0);
    for (field, value) in [
        ("reason", json!(" ")),
        ("reason", json!("x".repeat(4097))),
        ("unexpected", json!(true)),
    ] {
        let mut input = valid.clone();
        input[field] = value;
        assert!(f.call("findings:goal-assess", input).is_err());
    }
    let mut input = valid.clone();
    input["basis"]["snapshotHash"] = json!("forged");
    assert!(f.call("findings:goal-assess", input).is_err());
    let mut input = valid.clone();
    input["briefRef"]["revision"] = json!(99);
    assert!(f.call("findings:goal-assess", input).is_err());
    assert!(f
        .call("findings:goals", json!({"filter":"made-up"}))
        .is_err());
    assert!(f.call("findings:goals", json!({"offset":-1})).is_err());
    assert!(f
        .store
        .finding_goal_history(page["rows"][0]["basis"]["findingId"].as_i64().unwrap())
        .unwrap()
        .is_empty());
}

mod concurrency;

mod export;
