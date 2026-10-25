use super::*;
use crate::ModuleRegistry;
use serde_json::json;

#[test]
fn agentic_turn_limit_ownership_leaves_shared_model_and_reasoning_options_intact() {
    let input = json!({"taskMode":"manual","tasks":["secret-scan"],
        "agenticMaxModelTurns":3,"model":"explicit-operator-model","thinkingLevel":"medium","maxInventoryFiles":30});
    let before = input.clone();
    let groups = inactive_scan_task_options(&input).unwrap();
    assert_eq!(
        groups,
        vec![InactiveScanTaskOptions {
            task: "agentic".into(),
            options: vec!["agenticMaxModelTurns".into()]
        }]
    );
    assert!(crate::modules::scan_planning::validate_study_scan_selection(&input).is_err());
    let mut active = input.clone();
    active["tasks"] = json!(["agentic"]);
    assert!(inactive_scan_task_options(&active).unwrap().is_empty());
    assert_eq!(input, before);
}

#[test]
fn descriptor_owned_options_follow_canonical_aliases_and_explicit_false_values() {
    let registry = ModuleRegistry::with_v2_builtins();
    let input = registry
        .prepare_tool_input(
            "sast:scan",
            json!({
                "taskMode":"manual", "tasks":["secret-scan"], "semgrep_timeout_ms":1000,
                "cargo_audit_offline":false, "iacScanMaxEntries":10, "secretScanMaxEntries":20
            }),
            None,
        )
        .unwrap();
    let before = input.clone();
    let groups = inactive_scan_task_options(&input).unwrap();
    assert_eq!(
        groups,
        vec![
            InactiveScanTaskOptions {
                task: "semgrep".into(),
                options: vec!["semgrepTimeoutMs".into()]
            },
            InactiveScanTaskOptions {
                task: "cargo-audit".into(),
                options: vec!["cargoAuditOffline".into()]
            },
            InactiveScanTaskOptions {
                task: "iac-scan".into(),
                options: vec!["iacScanMaxEntries".into()]
            },
        ]
    );
    assert_eq!(input, before);
}

#[test]
fn selected_engine_settings_and_unrelated_options_are_preserved() {
    let input = json!({"taskMode":"manual","tasks":["semgrep","secret-scan"],
        "semgrepConfig":["operator.yml"],"secretScanMaxEntries":5,"maxFindings":7});
    let before = input.clone();
    assert!(inactive_scan_task_options(&input).unwrap().is_empty());
    assert_eq!(input, before);
}

#[test]
fn null_presence_agrees_with_existing_task_settings_readers() {
    let input = json!({"taskMode":"manual","tasks":["agentic"],
        "semgrepConfig":null,"cargoAuditOffline":null,"secretScanMaxEntries":null,"iacScanMaxEntries":null});
    let groups = inactive_scan_task_options(&input).unwrap();
    assert_eq!(
        groups
            .iter()
            .map(|group| group.task.as_str())
            .collect::<Vec<_>>(),
        vec!["secret-scan", "iac-scan"]
    );
    for key in [
        "semgrepConfig",
        "cargoAuditOffline",
        "secretScanMaxEntries",
        "iacScanMaxEntries",
    ] {
        let mut single = json!({"taskMode":"manual","tasks":["agentic"]});
        single[key] = Value::Null;
        let inactive = !inactive_scan_task_options(&single).unwrap().is_empty();
        assert_eq!(
            inactive,
            crate::modules::scan_planning::validate_study_scan_selection(&single).is_err(),
            "{key}"
        );
    }
}

#[test]
fn automatic_and_disabled_task_requests_use_shared_selection_policy() {
    let input = json!({"semgrepJobs":1,"secretScanMaxEntries":10});
    assert!(inactive_scan_task_options(&input).unwrap().is_empty());
    let groups = inactive_scan_task_options(
        &json!({"disabledTasks":["semgrep"],"semgrepJobs":1,"secretScanMaxEntries":10}),
    )
    .unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].task, "semgrep");
}

#[test]
fn malformed_or_unregistered_tasks_cannot_authorize_option_removal() {
    for input in [
        json!({"taskMode":"manual","tasks":[]}),
        json!({"taskMode":"manual","tasks":["unregistered-engine"]}),
    ] {
        assert!(inactive_scan_task_options(&input).is_err());
    }
}
