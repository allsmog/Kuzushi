use super::*;

fn test_context<'a>(
    workspace: &'a crate::WorkspaceTarget,
    config: &'a crate::V2Config,
    store: Option<&'a crate::FindingStore>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: store,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[cfg(unix)]
fn sleeping_scanner(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let binary = root.join("scanner.sh");
    std::fs::write(&binary, "#!/bin/sh\nsleep 60\n").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    binary
}

#[test]
fn semgrep_deadlines_prepare_canonical_aliases_and_reject_unused_or_invalid_limits() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = test_context(&workspace, &config, None);
    let registry = ModuleRegistry::with_v2_builtins();
    let input =
        json!({"taskMode":"manual","tasks":["semgrep"],"semgrep_timeout_ms":250,"semgrepJobs":3});
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input.clone(), &ctx, None)
        .unwrap();
    assert_eq!(prepared.value()["semgrepTimeoutMs"], 250);
    assert_eq!(prepared.value()["semgrepJobs"], 3);
    let standalone = registry
        .prepare_dispatch_input("semgrep:scan", json!({"timeout_ms":250}), &ctx, None)
        .unwrap();
    assert_eq!(standalone.value()["timeoutMs"], 250);
    assert_eq!(standalone.value()["jobs"], 1);
    let mut unused = input;
    unused["tasks"] = json!(["license-scan"]);
    assert!(registry
        .prepare_dispatch_input("sast:scan", unused, &ctx, None)
        .unwrap_err()
        .to_string()
        .contains("require the semgrep task"));
    for value in [0, crate::scan::MAX_SEMGREP_JOB_TIMEOUT_MS + 1] {
        assert!(registry
            .prepare_dispatch_input("semgrep:scan", json!({"timeoutMs":value}), &ctx, None)
            .is_err());
        assert!(registry
            .prepare_dispatch_input(
                "sast:scan",
                json!({"tasks":["semgrep"],"semgrepTimeoutMs":value}),
                &ctx,
                None
            )
            .is_err());
    }
    assert!(!workspace.root().join(".kuzushi/v3/runs").exists());
}

#[test]
fn prepared_semgrep_workers_reach_the_selected_engine() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = test_context(&workspace, &config, None);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"taskMode":"manual","tasks":["semgrep"],"semgrepJobs":3}),
            &ctx,
            None,
        )
        .unwrap();
    let selected = prepare_sast_task_selection(prepared.value()).unwrap();
    assert_eq!(
        selected.scanners[0].inspection_receipts()[0]["configuredLimits"]["jobs"],
        3
    );
}

#[test]
fn semgrep_worker_options_reject_invalid_and_unselected_requests() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = test_context(&workspace, &config, None);
    let registry = ModuleRegistry::with_v2_builtins();
    for value in [0, 257] {
        assert!(registry
            .prepare_dispatch_input("semgrep:scan", json!({"jobs":value}), &ctx, None)
            .is_err());
        assert!(registry
            .prepare_dispatch_input(
                "sast:scan",
                json!({"tasks":["semgrep"],"semgrepJobs":value}),
                &ctx,
                None
            )
            .is_err());
    }
    assert!(registry
        .prepare_dispatch_input(
            "sast:scan",
            json!({"taskMode":"manual","tasks":["license-scan"],"semgrepJobs":2}),
            &ctx,
            None
        )
        .is_err());
}

#[cfg(unix)]
#[test]
fn prepared_standalone_semgrep_deadline_is_a_failure_with_recorded_limits() {
    let fixture = tempfile::tempdir().unwrap();
    let source = fixture.path().join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("notice.py"),
        "print('Labeled policy fixture')\n",
    )
    .unwrap();
    let binary = sleeping_scanner(fixture.path());
    let workspace = crate::WorkspaceTarget::new(&source).unwrap();
    let config = crate::V2Config::default();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = test_context(&workspace, &config, Some(&store));
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(
            "semgrep:scan",
            json!({"binary":binary,"config":"labeled-test","timeoutMs":100}),
            &ctx,
            None,
        )
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_failed_deadline_result(&result);
    assert!(store.list_all_findings().unwrap().is_empty());
}

fn assert_failed_deadline_result(result: &Value) {
    assert_eq!(
        crate::tool_result_status(&result),
        crate::ToolResultStatus::Failed
    );
    assert!(
        result["output"].as_str().unwrap().contains("deadline"),
        "{result}"
    );
    assert_eq!(
        result["data"]["nativeInspections"][0]["configuredLimits"]["timeoutMs"],
        100
    );
    assert!(result["data"]["nativeInspections"][0]["started"]
        .as_bool()
        .unwrap());
}
