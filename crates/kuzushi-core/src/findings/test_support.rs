use super::{
    PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification,
    VerificationProvenance,
};
use crate::run_lifecycle::SafeText;
use crate::workflow_attempts::TargetContentIdentity;

pub(crate) fn empirically_verified(proof_level: u8) -> PersistedVerification {
    PersistedVerification {
        proof_level,
        proof_verdict: PersistedProofVerdict::Exploited,
        backend: PersistedSandboxBackend::Bwrap,
        language: Some("javascript".to_string()),
        harness_path: None,
        crash_evidence: None,
        duration_ms: 321,
        cost_usd: 0.0,
        notes: Vec::new(),
        verification_run_id: Some("verify-run".to_string()),
        verified_scan_id: Some("scan-1".to_string()),
        provenance: Some(VerificationProvenance {
            source_identity: TargetContentIdentity::IndexedSnapshot {
                snapshot_hash: SafeText::operator_visible("a".repeat(64)),
                tree_hash: Some(SafeText::operator_visible("b".repeat(64))),
            },
            reproducer: Some(
                serde_json::from_value(serde_json::json!({
                    "kind": "proof-snapshot",
                    "hash": "c".repeat(64),
                    "sizeBytes": 1
                }))
                .expect("test proof-snapshot reference"),
            ),
        }),
        created_at: "now".to_string(),
    }
}

/// One stored finding in a real workspace ledger, for tests that exercise
/// review-decision gating through the store (and the tool registry).
pub(crate) struct ReviewedFindingFixture {
    _dir: tempfile::TempDir,
    pub(crate) workspace: crate::workspace::WorkspaceTarget,
    pub(crate) store: super::FindingStore,
    finding_id: i64,
}

impl ReviewedFindingFixture {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("fixture tempdir");
        let workspace = crate::workspace::WorkspaceTarget::new(dir.path()).expect("workspace");
        let store = super::FindingStore::open(workspace.findings_db_path()).expect("store");
        store
            .record_run_started("run-1", workspace.root(), "completed")
            .expect("run started");
        let finding = super::Finding::new_semgrep(
            "demo.secret",
            "src/key.ts",
            1,
            Some(1),
            super::Severity::High,
            "hardcoded RSA private key",
        );
        let finding_id = store.insert_finding("run-1", &finding).expect("finding");
        Self {
            _dir: dir,
            workspace,
            store,
            finding_id,
        }
    }

    pub(crate) fn finding(&self) -> super::Finding {
        self.store
            .list_all_findings()
            .expect("findings")
            .into_iter()
            .find(|finding| finding.id == Some(self.finding_id))
            .expect("fixture finding")
    }

    pub(crate) fn record_auto_triage(&self, verdict: super::TriageVerdict) {
        let outcome = super::TriageOutcome {
            verdict,
            confidence: 0.9,
            rationale: "automated triage".to_string(),
            ..Default::default()
        };
        self.store
            .record_auto_triage(self.finding_id, &outcome)
            .expect("auto triage");
    }

    pub(crate) fn record_human_decision(&self, verdict: super::ReviewDecisionVerdict) {
        let decision = super::ReviewDecision {
            verdict,
            author: super::TriageAuthor::Human,
            confidence: 1.0,
            rationale: "operator review".to_string(),
            dismiss_reason: None,
            actor: Some("operator".to_string()),
        };
        self.store
            .append_user_review_decision(self.finding_id, &decision)
            .expect("human decision");
    }
}
