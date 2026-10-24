use super::*;
use crate::run_artifacts::{list_recent_run_summary_entries, write_run_summary, RunSummary};

fn write_history(root: &Path, tools: &[&str]) {
    for (index, tool) in tools.iter().enumerate() {
        let summary = RunSummary::running(
            format!("metadata-{index}"),
            "tool",
            Some((*tool).into()),
            root.display().to_string(),
        )
        .complete();
        write_run_summary(root, &summary).unwrap();
    }
    list_recent_run_summary_entries(root, tools.len().max(1)).unwrap();
}

#[test]
fn empty_target_and_current_operational_history_still_require_setup() {
    let root = tempfile::tempdir().unwrap();
    let registry = ModuleRegistry::with_v2_builtins();
    assert!(!registry
        .investigation_history_requires_resume(root.path())
        .unwrap());
    write_history(
        root.path(),
        &[
            "config:show",
            "router:show",
            "workspace:status",
            "threat-model:methodologies",
            "engagement:aim",
        ],
    );
    assert!(!registry
        .investigation_history_requires_resume(root.path())
        .unwrap());
}

#[test]
fn context_catalog_readers_do_not_establish_an_investigation() {
    for tool in [
        "threat-model:models",
        "threat-model:revisions",
        "threat-model:diff",
    ] {
        let root = tempfile::tempdir().unwrap();
        write_history(root.path(), &[tool]);
        assert!(
            !ModuleRegistry::with_v2_builtins()
                .investigation_history_requires_resume(root.path())
                .unwrap(),
            "{tool} lists or compares context; it does not produce a Map"
        );
    }
}

#[test]
fn genuine_or_unclassified_history_preserves_resume_without_granting_completion() {
    for tool in ["threat-model:build", "external:old-tool"] {
        let root = tempfile::tempdir().unwrap();
        write_history(root.path(), &["workspace:status", tool]);
        assert!(ModuleRegistry::with_v2_builtins()
            .investigation_history_requires_resume(root.path())
            .unwrap());
    }
}

#[test]
fn auxiliary_receipts_without_source_artifacts_still_require_setup() {
    let root = tempfile::tempdir().unwrap();
    write_history(
        root.path(),
        &[
            "context:build",
            "threat-intel:apply",
            "threat-intel:list",
            "findings:chains",
            "taint-iris-next:import-sinks",
        ],
    );
    assert!(!ModuleRegistry::with_v2_builtins()
        .investigation_history_requires_resume(root.path())
        .unwrap());
}

#[test]
fn larger_history_is_not_scanned_to_claim_the_target_is_fresh() {
    let root = tempfile::tempdir().unwrap();
    write_history(
        root.path(),
        &vec!["workspace:status"; STARTUP_HISTORY_LIMIT + 1],
    );
    assert!(ModuleRegistry::with_v2_builtins()
        .investigation_history_requires_resume(root.path())
        .unwrap());
}

#[test]
fn cold_or_invalid_history_is_left_unrepaired() {
    let root = tempfile::tempdir().unwrap();
    let bad = crate::run_artifacts::runs_root(root.path()).join("unreadable/metadata.json");
    std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
    std::fs::write(&bad, "invalid metadata").unwrap();
    assert!(ModuleRegistry::with_v2_builtins()
        .investigation_history_requires_resume(root.path())
        .unwrap());
    assert_eq!(std::fs::read_to_string(bad).unwrap(), "invalid metadata");
}
