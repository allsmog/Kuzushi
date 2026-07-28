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
