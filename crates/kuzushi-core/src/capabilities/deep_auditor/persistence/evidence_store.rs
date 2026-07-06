use super::super::domain::EvidenceCitation;
use crate::findings::FindingStore;
use anyhow::Result;

pub fn record_evidence(
    store: &FindingStore,
    finding_id: i64,
    evidence: &[EvidenceCitation],
) -> Result<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    store.record_finding_audit_event(
        finding_id,
        "deep-auditor",
        "deep-audit:evidence",
        format!("deep auditor recorded {} evidence citation(s)", evidence.len()),
        serde_json::json!({ "evidence": evidence }),
    )
}
