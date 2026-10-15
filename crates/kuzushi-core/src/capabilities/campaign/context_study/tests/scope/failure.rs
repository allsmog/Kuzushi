use super::*;

fn failed_scope() -> (tempfile::TempDir, ContextStudyReceipt) {
    let (root, workspace, config, reference) = scope_target();
    ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "campaign:context-study",
            scope_plan(&reference),
            &context(&workspace, &config),
        )
        .unwrap();
    let receipt = load_context_study(root.path(), "scope-draft").unwrap();
    write_json_atomic(
        &campaign_queue_path(root.path(), "scope-draft"),
        &json!({"jobs":{"context-001":{"state":"failed","attempts":1,"runId":"rejected-scope"}}}),
    )
    .unwrap();
    publish(root.path(), "input.json", &receipt.input);
    publish(
        root.path(),
        "result.json",
        &json!({"status":"failed",
        "data":{"tool":"pack:suggest-scopes","error":"unknown shared dependency greeting"}}),
    );
    (root, receipt)
}

fn publish(root: &Path, leaf: &str, value: &Value) {
    let label = if leaf == "input.json" {
        "tool input"
    } else {
        "tool result"
    };
    crate::run_artifacts::write_run_artifact_json(root, "rejected-scope", leaf, label, value)
        .unwrap();
}

#[test]
fn failed_scope_surfaces_exact_recorded_cause_without_replacing_original_draft() {
    let (root, receipt) = failed_scope();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let reference = serde_json::from_value(receipt.input["proposalRef"].clone()).unwrap();
    let before = crate::workspace::load_scan_scope_proposal(&workspace, &reference).unwrap();
    let error = receipt.generated_scopes(root.path()).unwrap_err();
    assert!(format!("{error:#}")
        .contains("Scope proposal rejected: unknown shared dependency greeting"));
    assert!(format!("{error:#}").contains("is failed"));
    assert_eq!(
        crate::workspace::load_scan_scope_proposal(&workspace, &reference).unwrap(),
        before
    );
    assert!(!root
        .path()
        .join(".kuzushi/threat-models/manifest.json")
        .exists());
}

#[test]
fn changed_result_foreign_inputs_and_foreign_tools_cannot_supply_a_failure_reason() {
    for damage in ["result", "input", "tool"] {
        let (root, receipt) = failed_scope();
        match damage {
            "result" => std::fs::write(root.path().join(".kuzushi/v3/runs/rejected-scope/result.json"),
                json!({"status":"failed","data":{"tool":"pack:suggest-scopes","error":"Injected reason"}}).to_string()).unwrap(),
            "input" => publish(root.path(), "input.json", &json!({"model":"foreign:model"})),
            _ => publish(root.path(), "result.json", &json!({"status":"failed","data":{"tool":"foreign:tool","error":"Injected reason"}})),
        }
        let error = format!("{:#}", receipt.generated_scopes(root.path()).unwrap_err());
        assert!(
            error.contains("Recorded scope failure unavailable"),
            "{damage}: {error}"
        );
        assert!(!error.contains("Injected reason"));
        assert!(error.contains("is failed"));
    }
}

#[test]
fn diagnostic_reason_is_bounded_and_escapes_terminal_controls() {
    let (root, receipt) = failed_scope();
    publish(
        root.path(),
        "result.json",
        &json!({"status":"failed","data":{
        "tool":"pack:suggest-scopes","error":format!("\u{1b}[31m{}", "界".repeat(2000))}}),
    );
    let error = receipt
        .generated_scopes(root.path())
        .unwrap_err()
        .to_string();
    assert!(!error.contains('\u{1b}'));
    assert!(error.contains("\\u{1b}[31m"));
    assert!(error.chars().count() < 1100);
}
