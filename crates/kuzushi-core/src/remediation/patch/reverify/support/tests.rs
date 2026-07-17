use super::*;
use crate::findings::{PatchProvenance, PatchResult, Severity};
use crate::run_artifacts::{
    read_run_artifact_text, record_tool_run_started, RunArtifactRead, ToolRunRecord,
};
use std::path::Path;

fn lifecycle_record(fingerprint: &str) -> PatchLifecycleRecord {
    PatchLifecycleRecord {
        application_id: "application-1".to_string(),
        stable_fp: "stable-1".to_string(),
        fingerprint: fingerprint.to_string(),
        finding_scan_id: Some("scan-1".to_string()),
        patch_run_id: "patch-run-1".to_string(),
        target: "/tmp/target".to_string(),
        diff_hash: "sha256:diff".to_string(),
        base_commit: None,
        touched_files: Vec::new(),
        state: PatchLifecycleState::Applied,
        reverify_run_id: None,
        detail: None,
        actor: "operator".to_string(),
        application_started_at: "1".to_string(),
        applied_at: Some("1".to_string()),
        updated_at: "1".to_string(),
    }
}

#[test]
fn detector_absence_never_overclaims_nondeterministic_success() {
    assert_eq!(absence_outcome(true), PatchLifecycleState::Verified);
    assert_eq!(absence_outcome(false), PatchLifecycleState::NotRediscovered);
}

#[test]
fn rediscovery_matches_fingerprint_or_stable_identity() {
    let original = Finding::new_semgrep(
        "rule.one",
        "src/app.rs",
        3,
        Some(3),
        Severity::High,
        "finding",
    );
    let record = lifecycle_record(&original.fingerprint);
    let mut candidate = original.clone();
    assert!(same_finding(Some(&original), &candidate, &record));
    candidate.fingerprint = "new-observation".to_string();
    candidate.identity_id = Some("identity-1".to_string());
    let mut with_identity = original;
    with_identity.identity_id = Some("identity-1".to_string());
    assert!(same_finding(Some(&with_identity), &candidate, &record));
    candidate.identity_id = Some("identity-2".to_string());
    assert!(!same_finding(Some(&with_identity), &candidate, &record));
}

#[test]
fn stored_touched_paths_cannot_escape_the_active_target() {
    assert!(ensure_relative_touched_path("src/app.rs").is_ok());
    assert!(ensure_relative_touched_path("../outside.rs").is_err());
    assert!(ensure_relative_touched_path("/tmp/outside.rs").is_err());
}

#[test]
fn detector_failure_detail_is_never_blank() {
    assert_eq!(
        detector_failure_detail(&json!({"errors": []})),
        "originating detector returned a failure result"
    );
    assert_eq!(
        detector_failure_detail(&json!({"errors": ["boom", "bad input"]})),
        "boom; bad input"
    );
}

#[test]
fn legacy_patch_without_provenance_requires_regeneration() {
    let target = tempfile::tempdir().unwrap();
    let store =
        crate::findings::FindingStore::open(target.path().join(".kuzushi/v3/index.sqlite3"))
            .unwrap();
    store
        .record_run_started("scan-1", target.path(), "completed")
        .unwrap();
    let finding = Finding::new_semgrep(
        "rule.one",
        "src/app.rs",
        3,
        Some(3),
        Severity::High,
        "finding",
    );
    store.insert_finding("scan-1", &finding).unwrap();
    store
        .insert_patch_result(&PatchResult {
            patch_run_id: "patch-run-1".to_string(),
            fingerprint: finding.fingerprint.clone(),
            repo: target.path().display().to_string(),
            diff: Some("diff --git a/src/app.rs b/src/app.rs\n".to_string()),
            status: PatchStatus::Sound,
            iterations: 1,
            build_command: None,
            test_command: None,
            worktree_path: None,
            cost_usd: Some(0.0),
            provider_spend_unresolved: false,
            validator_log: None,
            history: Vec::new(),
            provenance: None,
            created_at: None,
            updated_at: None,
        })
        .unwrap();
    let record = lifecycle_record(&finding.fingerprint);

    let error = originating_detector_binding(&store, target.path(), &record)
        .unwrap_err()
        .to_string();

    assert!(error.contains("legacy patch"));
    assert!(error.contains("regenerate"));
}

#[test]
fn module_only_provenance_replays_the_exact_qualified_detector() {
    let target = tempfile::tempdir().unwrap();
    let store =
        crate::findings::FindingStore::open(target.path().join(".kuzushi/v3/index.sqlite3"))
            .unwrap();
    let finding = persisted_detector_finding(&store, target.path());
    let detector_input = persisted_detector_input(target.path());
    persist_bound_patch(&store, target.path(), &finding, &detector_input);
    let mut record = lifecycle_record(&finding.fingerprint);
    record.base_commit = Some("source-commit".to_string());
    record.finding_scan_id = finding.scan_id.clone();

    let binding = originating_detector_binding(&store, target.path(), &record).unwrap();

    assert_eq!(binding.tool, "secret-scan:scan");
    assert_eq!(binding.run_id, "secret-run");
    assert_eq!(binding.input, json!({"depth": "full"}));
}

#[test]
fn legacy_application_without_generation_requires_inconclusive_regeneration() {
    let target = tempfile::tempdir().unwrap();
    let store =
        crate::findings::FindingStore::open(target.path().join(".kuzushi/v3/index.sqlite3"))
            .unwrap();
    let finding = persisted_detector_finding(&store, target.path());
    let detector_input = persisted_detector_input(target.path());
    persist_bound_patch(&store, target.path(), &finding, &detector_input);
    let mut record = lifecycle_record(&finding.fingerprint);
    record.base_commit = Some("source-commit".to_string());
    record.finding_scan_id = None;

    let error = originating_detector_binding(&store, target.path(), &record)
        .unwrap_err()
        .to_string();

    assert!(error.contains("legacy patch application"), "{error}");
    assert!(error.contains("regenerate"), "{error}");
}

fn persisted_detector_finding(store: &crate::findings::FindingStore, target: &Path) -> Finding {
    store
        .record_run_started("secret-run", target, "completed")
        .unwrap();
    let mut finding = Finding::new_tool(
        "secret-scan",
        "secret/key",
        "config.env",
        1,
        Some(1),
        Severity::High,
        "exposed key",
    );
    finding.scan_id = Some("secret-run".to_string());
    store.insert_finding("secret-run", &finding).unwrap();
    finding
}

fn persisted_detector_input(target: &Path) -> String {
    record_tool_run_started(
        ToolRunRecord::new(target, "secret-run", "tool", "secret-scan:scan"),
        &json!({"depth": "full"}),
    );
    let RunArtifactRead::Ready { value, .. } =
        read_run_artifact_text(target, "secret-run", "input.json")
    else {
        panic!("detector input artifact");
    };
    value
}

fn persist_bound_patch(
    store: &crate::findings::FindingStore,
    target: &Path,
    finding: &Finding,
    detector_input: &str,
) {
    let patch = PatchResult {
        patch_run_id: "patch-run-1".to_string(),
        fingerprint: finding.fingerprint.clone(),
        repo: target.display().to_string(),
        diff: Some("diff --git a/config.env b/config.env\n".to_string()),
        status: PatchStatus::Sound,
        iterations: 1,
        build_command: None,
        test_command: None,
        worktree_path: None,
        cost_usd: Some(0.0),
        provider_spend_unresolved: false,
        validator_log: None,
        history: Vec::new(),
        provenance: Some(PatchProvenance {
            source_commit: "source-commit".to_string(),
            target: target.display().to_string(),
            originating_run_id: Some("patch-tool-run".to_string()),
            detector_tool: Some("secret-scan".to_string()),
            detector_run_id: Some("secret-run".to_string()),
            detector_input_digest: Some(PatchProvenance::digest_detector_input(
                detector_input.as_bytes(),
            )),
        }),
        created_at: None,
        updated_at: None,
    };
    store.insert_patch_result(&patch).unwrap();
}
