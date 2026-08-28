use super::*;
use serde_json::json;

fn resolve(input: Value, workers: usize) -> ParallelSafetyResolution {
    resolve_parallel_safety(
        &ModuleRegistry::with_v2_builtins(),
        SAST_SCAN_TOOL,
        &input,
        workers,
    )
    .unwrap()
}

#[test]
fn automatic_selection_is_unknown_and_clamped() {
    let resolution = resolve(json!({"taskMode": "auto"}), 4);
    assert_eq!(resolution.safety, ParallelSafety::Unknown);
    assert_eq!(resolution.effective_workers, 1);
    assert!(resolution.clamp_reason.unwrap().contains("automatic"));
}

#[test]
fn shared_read_tasks_use_requested_workers_up_to_dispatcher_cap() {
    let input = json!({"taskMode": "manual", "tasks": ["secret-scan", "iac-scan"]});
    assert_eq!(resolve(input.clone(), 4).effective_workers, 4);
    let capped = resolve(input, MAX_CAMPAIGN_WORKERS + 2);
    assert_eq!(capped.effective_workers, MAX_CAMPAIGN_WORKERS);
    assert!(capped.clamp_reason.unwrap().contains("dispatcher cap"));
}

#[test]
fn codeql_task_names_its_exclusive_workspace_resource() {
    let resolution = resolve(json!({"taskMode": "manual", "tasks": ["codeql:scan"]}), 4);
    assert_eq!(resolution.effective_workers, 1);
    assert_eq!(
        resolution.safety,
        workspace_exclusive("workspace-codeql-database")
    );
    let reason = resolution.clamp_reason.unwrap();
    assert!(reason.contains("codeql"));
    assert!(reason.contains("workspace-codeql-database"));
}

#[test]
fn cpg_backed_taint_task_names_its_exclusive_graph() {
    let resolution = resolve(
        json!({"taskMode": "manual", "tasks": ["taint-iris-next"], "backend": "cpg-rs"}),
        3,
    );
    assert_eq!(resolution.effective_workers, 1);
    assert_eq!(
        resolution.safety,
        workspace_exclusive("workspace-cpg-rs-graph")
    );
}

#[test]
fn unresolved_taint_backend_fails_safe() {
    let resolution = resolve(
        json!({"taskMode": "manual", "tasks": ["taint-iris-next"], "backend": "auto"}),
        3,
    );
    assert_eq!(resolution.safety, ParallelSafety::Unknown);
    assert_eq!(resolution.effective_workers, 1);
}

#[test]
fn unknown_manual_task_fails_safe_and_names_the_task() {
    let resolution = resolve(json!({"taskMode": "manual", "tasks": ["future-engine"]}), 3);
    assert_eq!(resolution.effective_workers, 1);
    assert!(resolution.clamp_reason.unwrap().contains("future-engine"));
}

#[test]
fn zero_requested_workers_is_rejected() {
    let error = resolve_parallel_safety(
        &ModuleRegistry::with_v2_builtins(),
        SAST_SCAN_TOOL,
        &json!({"taskMode": "auto"}),
        0,
    )
    .unwrap_err();
    assert!(error.to_string().contains("at least 1"));
}
