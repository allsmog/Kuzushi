use super::*;
use kuzushi_core::{
    FindingEvidence, FindingStore, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, Severity, StaticProofState, VerificationProvenance, WorkspaceTarget,
};
use std::path::{Path, PathBuf};

type FindingSeed = (Severity, &'static str, u32, &'static str);
const REFERENCE_SCAN_ID: &str = "discovery-phase-run";

const REFERENCE_FINDINGS: [FindingSeed; 6] = [
    (
        Severity::Critical,
        "src/auth/login.rs",
        17,
        "SQL injection reaches query",
    ),
    (
        Severity::High,
        "src/web/template.rs",
        8,
        "Template input reaches renderer",
    ),
    (
        Severity::High,
        "src/api/orders.rs",
        31,
        "Order identifier crosses trust boundary",
    ),
    (
        Severity::Medium,
        "src/auth/session.rs",
        12,
        "Session cookie lacks rotation",
    ),
    (
        Severity::Medium,
        "src/api/upload.rs",
        44,
        "Upload type is trusted",
    ),
    (
        Severity::Low,
        "src/config.rs",
        5,
        "Debug endpoint remains enabled",
    ),
];

pub(super) fn seed(app: &mut ShellApp, target: &Path) -> Result<(), String> {
    let mut findings = reference_findings();
    let reproducer = reference_proof_snapshot(target)?;
    add_runtime_proof(&mut findings[0], reproducer);
    persist_reference_findings(target, &findings)?;
    let selected = findings[0].clone();
    let counts = crate::ui_view_models::finding_ledger_counts(
        &findings,
        app.review_decisions(),
        REFERENCE_FINDINGS.len(),
    );
    *app.findings_mut() = findings;
    app.set_findings_total_count(REFERENCE_FINDINGS.len());
    app.domain_mut().set_finding_ledger_counts(counts);
    *app.selected_finding_mut() = Some(selected);
    app.router.findings_mut().set_cursor(0);
    Ok(())
}

fn reference_proof_snapshot(
    target: &Path,
) -> Result<kuzushi_core::content_store::ObjectRef, String> {
    let workspace = WorkspaceTarget::new(target).map_err(|error| error.to_string())?;
    kuzushi_core::content_store::ContentStore::open(workspace.objects_dir())
        .map_err(|error| error.to_string())?
        .put_json(
            kuzushi_core::content_store::ObjectKind::ProofSnapshot,
            &serde_json::json!({"schemaVersion": 1, "fixture": "phase-reference"}),
        )
        .map_err(|error| error.to_string())
}

fn persist_reference_findings(target: &Path, findings: &[Finding]) -> Result<(), String> {
    let workspace = WorkspaceTarget::new(target).map_err(|error| error.to_string())?;
    let database = workspace.findings_db_path();
    reset_finding_store(&database, &workspace.event_log_dir())?;
    let store = FindingStore::open(&database).map_err(|error| error.to_string())?;
    store
        .record_run_started(REFERENCE_SCAN_ID, target, "running")
        .map_err(|error| error.to_string())?;
    let ids = store
        .insert_findings(REFERENCE_SCAN_ID, findings)
        .map_err(|error| error.to_string())?;
    if let Some((finding_id, verification)) = ids.first().zip(findings[0].verification.as_ref()) {
        store
            .save_verification(*finding_id, verification)
            .map_err(|error| error.to_string())?;
    }
    store
        .record_run_finished(REFERENCE_SCAN_ID, "completed", findings.len())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn reset_finding_store(database: &Path, event_log: &Path) -> Result<(), String> {
    match std::fs::remove_dir_all(event_log) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("reset {}: {error}", event_log.display())),
    }
    for path in database_files(database) {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("reset {}: {error}", path.display())),
        }
    }
    Ok(())
}

fn database_files(database: &Path) -> [PathBuf; 3] {
    [
        database.to_path_buf(),
        database_sidecar(database, "-wal"),
        database_sidecar(database, "-shm"),
    ]
}

fn database_sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn reference_findings() -> Vec<Finding> {
    REFERENCE_FINDINGS
        .into_iter()
        .enumerate()
        .map(|(index, (severity, path, line, title))| {
            reference_finding(index, severity, path, line, title)
        })
        .collect()
}

fn add_runtime_proof(finding: &mut Finding, reproducer: kuzushi_core::content_store::ObjectRef) {
    finding.scan_id = Some(REFERENCE_SCAN_ID.to_string());
    finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
    finding.verification = Some(PersistedVerification {
        proof_level: 4,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend: PersistedSandboxBackend::Bwrap,
        language: Some("rust".to_string()),
        harness_path: Some(".kuzushi/harness/sql-injection.rs".to_string()),
        crash_evidence: Some("boolean payload changed the result set".to_string()),
        duration_ms: 842,
        cost_usd: 0.04,
        notes: vec!["isolated database fixture".to_string()],
        verification_run_id: Some("verify-phase-run".to_string()),
        verified_scan_id: Some(REFERENCE_SCAN_ID.to_string()),
        provenance: Some(VerificationProvenance {
            source_identity:
                kuzushi_core::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                    snapshot_hash: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                        "a".repeat(64),
                    ),
                    tree_hash: None,
                },
            reproducer: Some(reproducer),
        }),
        created_at: "2026-07-09T19:54:48Z".to_string(),
    });
}

fn reference_finding(
    index: usize,
    severity: Severity,
    path: &str,
    line: u32,
    title: &str,
) -> Finding {
    let mut finding = Finding::new_tool(
        "semgrep",
        format!("phase.rule.{index}"),
        path,
        line,
        None,
        severity,
        title,
    );
    finding.title = title.to_string();
    finding.identity_id = Some(format!("phase-finding-{index}"));
    finding.evidence = vec![source_sink_evidence(path, line)];
    finding
}

fn source_sink_evidence(path: &str, line: u32) -> FindingEvidence {
    FindingEvidence {
        kind: "source-sink".to_string(),
        file_path: path.to_string(),
        line,
        snippet: "request_input -> database_query".to_string(),
        rationale: "attacker-controlled input reaches a security boundary".to_string(),
        confidence: 94,
        request_blob: None,
        response_blob: None,
    }
}
