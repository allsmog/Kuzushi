//! A labeled scanner protocol fixture plus an operator edit, never target execution.
use crate::{
    Finding, FindingStore, ModuleRegistry, Severity, ToolExecutionContext, V2Config,
    WorkspaceTarget,
};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

fn paused_scanner(root: &Path) -> PathBuf {
    let path = root.join("owned-adapter.sh");
    fs::write(
        &path,
        r#"#!/bin/sh
adapter_root=${0%/*}
: > "$adapter_root/entered"
attempt=0
while [ ! -f "$adapter_root/proceed" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 500 ]; then exit 2; fi
  sleep 0.01
done
printf '%s\n' '{"results":[]}'
"#,
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn edit_after_scanner_starts(adapter: PathBuf, source: PathBuf) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        while !adapter.join("entered").is_file() {
            assert!(
                Instant::now() < deadline,
                "The owned scanner fixture did not start"
            );
            thread::sleep(Duration::from_millis(10));
        }
        fs::write(
            source,
            "// Planned operator edit during source-only analysis.\n",
        )
        .unwrap();
        fs::write(adapter.join("proceed"), "continue").unwrap();
    })
}

fn seed_observation(workspace: &WorkspaceTarget, store: &FindingStore) {
    store
        .record_run_started("before-edit", workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_semgrep(
        "owned.protocol",
        "src/lib.rs",
        1,
        None,
        Severity::Low,
        "Labeled prior metadata observation, not a verified vulnerability",
    );
    store.insert_finding("before-edit", &finding).unwrap();
    store
        .record_run_finished("before-edit", "completed", 1)
        .unwrap();
}

fn dispatch(workspace: &WorkspaceTarget, store: &FindingStore, binary: &Path) -> Value {
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = json!({"runId":"during-edit", "taskMode":"manual", "tasks":["semgrep"],
        "semgrepBinary":binary,"semgrepConfig":["owned-protocol-fixture"],"semgrepTimeoutMs":10000,
        "triage":false,"verify":false,"autoPatch":false});
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn source_drift_cannot_publish_completed_scan_coverage_or_record_absence() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    let source = root.path().join("src/lib.rs");
    fs::write(&source, "// Owned inert source. Never executed.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    seed_observation(&workspace, &store);
    let adapter = tempfile::tempdir().unwrap();
    let binary = paused_scanner(adapter.path());
    let editor = edit_after_scanner_starts(adapter.path().into(), source);
    let output = dispatch(&workspace, &store, &binary);
    editor.join().unwrap();
    assert_eq!(output["status"], "partial", "{output:#}");
    assert!(
        store.list_all_findings().unwrap()[0]
            .observation_gap
            .is_none(),
        "A post-scan source mismatch must not record covered absence"
    );
    assert_ne!(
        output["data"]["phaseStages"][0]["outcome"], "completed",
        "{output:#}"
    );
    assert_eq!(
        store.run_status("during-edit").unwrap().as_deref(),
        Some("partial")
    );
    let receipt = crate::run_artifacts::load_scan_stage_data(workspace.root(), "during-edit")
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.outcome,
        crate::run_artifacts::PhaseStageOutcome::Partial
    );
}
