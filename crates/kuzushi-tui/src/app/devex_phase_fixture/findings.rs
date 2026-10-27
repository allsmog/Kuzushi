use super::*;
use kuzushi_core::{
    FindingEvidence, FindingStore, PersistedProofVerdict, PersistedSandboxBackend,
    PersistedVerification, Severity, StaticProofState, VerificationProvenance,
    VerificationStageDisclosure, WorkspaceTarget,
};
use std::path::{Path, PathBuf};

type FindingSeed = (Severity, &'static str, u32, &'static str);
const REFERENCE_SCAN_ID: &str = "discovery-phase-run";

// F4 split-verdict fixtures: stable fingerprints so the P3 journeys can
// `open <fingerprint>` the seeded findings deterministically, plus the run ids
// whose items.jsonl carry the gate/panel/escalation stage labels.
pub(super) const ESCALATED_FINGERPRINT: &str = "escalated-split-fixture";
pub(super) const REFUSED_FINGERPRINT: &str = "refused-split-fixture";
// F4 deep-audit AUDITED DATAFLOW fixture: a finding carrying seeded
// `deep-audit:evidence` audit events (source/sink/guard citations mined off a
// cpg-rs path) so the Review detail pane and the Prove page render the AUDITED
// DATAFLOW section with a falsifying guard row, keyless.
pub(super) const AUDITED_FINGERPRINT: &str = "audited-dataflow-fixture";
pub(super) const ESCALATED_RUN_ID: &str = "verify-escalated-run";
pub(super) const REFUSED_RUN_ID: &str = "verify-refused-run";
pub(super) const GATE_MODEL: &str = "openai:gpt-cheap";
pub(super) const PANEL_MODEL: &str = "openai:gpt-verify";
pub(super) const ESCALATION_MODEL: &str = "openai:gpt-strong";

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
    add_escalated_split_proof(&mut findings[1]);
    add_refused_split_proof(&mut findings[2]);
    add_audited_dataflow_finding(&mut findings[4]);
    let generations = persist_reference_findings(target, &findings)?;
    bind_persisted_generations(&mut findings, &generations, target)?;
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

/// The in-memory ledger must name the generations the store actually holds:
/// a refresh reselects by exact generation, never by fingerprint alone.
fn bind_persisted_generations(
    findings: &mut [Finding],
    generations: &[i64],
    target: &Path,
) -> Result<(), String> {
    let workspace = WorkspaceTarget::new(target).map_err(|error| error.to_string())?;
    let store = FindingStore::open_read_only(workspace.findings_db_path())
        .map_err(|error| error.to_string())?;
    for (finding, id) in findings.iter_mut().zip(generations) {
        let stored = store
            .get_finding_by_reference(&format!("generation:{id}"))
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("Persisted reference generation {id} is unavailable"))?;
        finding.id = stored.id;
        finding.scan_id = stored.scan_id;
        finding.identity_id = stored.identity_id;
        finding.identity_basis = stored.identity_basis;
        finding.identity_match_tier = stored.identity_match_tier;
    }
    Ok(())
}

fn persist_reference_findings(target: &Path, findings: &[Finding]) -> Result<Vec<i64>, String> {
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
    for (finding_id, finding) in ids.iter().zip(findings) {
        if let Some(verification) = finding.verification.as_ref() {
            store
                .save_verification(*finding_id, verification)
                .map_err(|error| error.to_string())?;
        }
        if finding.fingerprint == AUDITED_FINGERPRINT {
            record_audited_dataflow(&store, *finding_id)?;
        }
    }
    store
        .record_run_finished(REFERENCE_SCAN_ID, "completed", findings.len())
        .map_err(|error| error.to_string())?;
    Ok(ids)
}

/// F4: record the deep-auditor's cited dataflow as `deep-audit:evidence` audit
/// events through the real `record_finding_audit_event` write path — the same
/// path the live auditor uses — so the detail-pane / Prove AUDITED DATAFLOW
/// section renders a source, a sink, and a falsifying `guard` witness mined off
/// a cpg-rs path (`origin: cpg_path`), keyless.
fn record_audited_dataflow(store: &FindingStore, finding_id: i64) -> Result<(), String> {
    let details = serde_json::json!({
        "evidence": [
            {
                "file": "src/api/upload.rs", "start_line": 31, "end_line": 31,
                "note": "multipart body flows into the upload handler",
                "kind": "source", "origin": "cpg_path"
            },
            {
                "file": "src/api/upload.rs", "start_line": 44, "end_line": 44,
                "note": "declared content-type is trusted at the write sink",
                "kind": "sink", "origin": "cpg_path"
            },
            {
                "file": "src/api/upload.rs", "start_line": 39, "end_line": 39,
                "note": "size ceiling only — no type allowlist on the path",
                "kind": "guard", "origin": "cpg_path"
            }
        ]
    });
    store
        .record_finding_audit_event(
            finding_id,
            "deep-auditor",
            kuzushi_core::findings::DATAFLOW_EVIDENCE_SUBJECT,
            "recorded deep-audit dataflow evidence",
            details,
        )
        .map_err(|error| error.to_string())
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

/// F4: a split-verdict panel that a DIFFERENT operator-named model broke on
/// tie. It stays a static model assessment — backend `Model` keeps the finding
/// `ModelAssessed`/Suspected, so the Prove ladder never advances a rung. The
/// stage note discloses the gate/panel/escalation ladder for the ⚖ Prove line.
fn add_escalated_split_proof(finding: &mut Finding) {
    finding.fingerprint = ESCALATED_FINGERPRINT.to_string();
    finding.scan_id = Some(REFERENCE_SCAN_ID.to_string());
    let disclosure = VerificationStageDisclosure {
        gate: Some(GATE_MODEL.to_string()),
        panel_passes: 2,
        split: true,
        escalation: Some(ESCALATION_MODEL.to_string()),
        refused: None,
    };
    finding.verification = Some(model_split_verification(
        &disclosure,
        ESCALATED_RUN_ID,
        "2026-07-09T19:55:00Z",
    ));
}

/// F4: a split-verdict panel whose requested escalation was refused because the
/// tie-break model matched the primary (`SameModelAsPrimary`). The split verdict
/// stands unchanged; the refusal renders in warn/danger tone, never a green ✓.
fn add_refused_split_proof(finding: &mut Finding) {
    finding.fingerprint = REFUSED_FINGERPRINT.to_string();
    finding.scan_id = Some(REFERENCE_SCAN_ID.to_string());
    let disclosure = VerificationStageDisclosure {
        gate: Some(GATE_MODEL.to_string()),
        panel_passes: 2,
        split: true,
        escalation: None,
        refused: Some("same-model".to_string()),
    };
    finding.verification = Some(model_split_verification(
        &disclosure,
        REFUSED_RUN_ID,
        "2026-07-09T19:55:30Z",
    ));
}

/// F4: give the medium `src/api/upload.rs` finding a stable fingerprint so the
/// P2 AUDITED DATAFLOW journey can `open audited-dataflow-fixture`
/// deterministically. Its proof state is untouched — the dataflow evidence must
/// not move a rung (deferred-promotion guard), so this only pins the id.
fn add_audited_dataflow_finding(finding: &mut Finding) {
    finding.fingerprint = AUDITED_FINGERPRINT.to_string();
    finding.scan_id = Some(REFERENCE_SCAN_ID.to_string());
}

fn model_split_verification(
    disclosure: &VerificationStageDisclosure,
    run_id: &str,
    created_at: &str,
) -> PersistedVerification {
    PersistedVerification {
        proof_level: 2,
        // A model assessment persists no runtime verdict — the split/escalation
        // story lives in the stage note, and the finding stays ModelAssessed.
        proof_verdict: PersistedProofVerdict::NotAttempted,
        backend: PersistedSandboxBackend::Model,
        language: None,
        harness_path: None,
        crash_evidence: None,
        duration_ms: 5123,
        cost_usd: 0.03,
        notes: vec![kuzushi_core::format_stage_note(disclosure)],
        verification_run_id: Some(run_id.to_string()),
        verified_scan_id: Some(REFERENCE_SCAN_ID.to_string()),
        provenance: None,
        created_at: created_at.to_string(),
    }
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
