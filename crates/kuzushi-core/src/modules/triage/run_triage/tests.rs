use super::*;

struct ReviewRuntime {
    source_to_change: Option<PathBuf>,
}

impl AgentRuntime for ReviewRuntime {
    fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
        if let Some(path) = &self.source_to_change {
            std::fs::write(path, "fn changed() {}\n")?;
        }
        Ok(TriageOutcome {
            verdict: TriageVerdict::FalsePositive,
            confidence: 0.9,
            rationale: "No reachable sink in the reviewed source".to_string(),
            cost_usd: 0.125,
            cost_usd_exact: true,
            ..Default::default()
        })
    }
}

fn dispatch_review(change_source: bool) -> Value {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("lib.rs");
    std::fs::write(&source, "fn candidate() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("scan", temp.path(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "audit",
        "rule",
        "lib.rs",
        1,
        None,
        Severity::High,
        "candidate",
    );
    store.insert_finding("scan", &finding).unwrap();
    let config = crate::config::V2Config {
        model: Some("openai:gpt-5.5".to_string()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let runtime = ReviewRuntime {
        source_to_change: change_source.then_some(source),
    };
    crate::modules::ModuleRegistry::with_v2_builtins()
        .execute_tool_with_runtime(
            "triage:run",
            json!({"prefilterThreshold": 0, "strategy": "standard"}),
            &ctx,
            Some(&runtime),
        )
        .unwrap()
}

#[test]
fn registry_triage_binds_success_to_source_and_preserves_outcome_and_spend() {
    let result = dispatch_review(false);
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["triaged"], 1);
    assert_eq!(result["data"]["fp"], 1);
    assert_eq!(result["data"]["costUsd"], 0.125);
    for field in ["snapshotHash", "treeHash"] {
        assert!(
            result["data"][field]
                .as_str()
                .is_some_and(|value| value.len() == 64),
            "missing {field}"
        );
    }
}

#[test]
fn registry_triage_source_change_is_partial_without_erasing_classification_or_cost() {
    let result = dispatch_review(true);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["triaged"], 1);
    assert_eq!(result["data"]["fp"], 1);
    assert_eq!(result["data"]["costUsd"], 0.125);
    assert!(result["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning
            .as_str()
            .is_some_and(|text| text.contains("source changed"))));
}
