//! Pure projection of deep-auditor `deep-audit:evidence` audit events into
//! rows for the finding detail / Prove surfaces. No IO — the caller supplies
//! the already-read [`FindingAuditEvent`] list.

use crate::findings::FindingAuditEvent;
use serde::Serialize;
use serde_json::Value;

/// The audit-event subject deep-auditor evidence is filed under.
pub const DATAFLOW_EVIDENCE_SUBJECT: &str = "deep-audit:evidence";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataflowEvidenceRow {
    /// Where the witness came from, e.g. "deep auditor (cpg-rs path)".
    pub origin: String,
    /// `file:line` or `file:start-end` location of the citation.
    pub location: String,
    /// Citation kind: source | sink | guard | context.
    pub kind: String,
    /// Human-readable note; guard rows are prefixed "falsifying evidence · ".
    pub note: String,
}

/// Flatten every `deep-audit:evidence` audit event's `details.evidence[]` into
/// ordered rows. Guard citations are labelled as falsifying evidence.
pub fn dataflow_evidence_rows(events: &[FindingAuditEvent]) -> Vec<DataflowEvidenceRow> {
    let mut rows = Vec::new();
    for event in events {
        for citation in citations_of(&event.details) {
            rows.push(evidence_row(citation));
        }
    }
    rows
}

fn citations_of(details: &Value) -> impl Iterator<Item = &Value> {
    details
        .get("evidence")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
}

fn evidence_row(citation: &Value) -> DataflowEvidenceRow {
    let kind = citation
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("context")
        .to_string();
    DataflowEvidenceRow {
        origin: origin_label(citation),
        location: citation_location(citation),
        note: citation_note(citation, &kind),
        kind,
    }
}

/// Origin is derived from the tracked `origin` marker set at citation
/// creation, NOT from `kind`: the prompt asks the model to emit `kind="guard"`
/// citations, so a guard tag alone is model provenance, not a cpg-rs witness.
/// Only citations mined by the dataflow engine carry `origin="cpg_path"`.
fn origin_label(citation: &Value) -> String {
    match citation.get("origin").and_then(Value::as_str) {
        Some("cpg_path") => "deep auditor (cpg-rs path)".to_string(),
        _ => "deep auditor (code read)".to_string(),
    }
}

fn citation_location(citation: &Value) -> String {
    let file = citation.get("file").and_then(Value::as_str).unwrap_or("?");
    let start = citation.get("start_line").and_then(Value::as_u64).unwrap_or(0);
    let end = citation.get("end_line").and_then(Value::as_u64).unwrap_or(start);
    if end > start {
        format!("{file}:{start}-{end}")
    } else {
        format!("{file}:{start}")
    }
}

fn citation_note(citation: &Value, kind: &str) -> String {
    let note = citation.get("note").and_then(Value::as_str).unwrap_or("");
    if kind == "guard" {
        return format!("falsifying evidence · {note}");
    }
    note.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(details: Value) -> FindingAuditEvent {
        FindingAuditEvent {
            seq: 1,
            actor: "deep-auditor".to_string(),
            subject: DATAFLOW_EVIDENCE_SUBJECT.to_string(),
            summary: "recorded evidence".to_string(),
            details,
            created_at: "2026-07-30T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn dataflow_evidence_rows_label_guard_rows_as_falsifying() {
        let events = vec![event(json!({
            "evidence": [
                {"file": "src/users.ts", "start_line": 91, "end_line": 91, "note": "authz gate", "kind": "guard"},
                {"file": "src/users.ts", "start_line": 12, "end_line": 12, "note": "user input", "kind": "source"}
            ]
        }))];
        let rows = dataflow_evidence_rows(&events);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].kind, "guard");
        assert_eq!(rows[0].location, "src/users.ts:91");
        // A guard row is always labelled falsifying evidence, regardless of
        // origin.
        assert!(rows[0].note.starts_with("falsifying evidence · "));
        assert_eq!(rows[1].kind, "source");
        assert!(!rows[1].note.starts_with("falsifying evidence"));
    }

    #[test]
    fn cpg_mined_citation_gets_cpg_rs_origin() {
        // A citation the taint tool mined carries origin="cpg_path" — the only
        // truthful source of cpg-rs provenance.
        let events = vec![event(json!({
            "evidence": [
                {"file": "src/db.ts", "start_line": 40, "end_line": 40,
                 "note": "cpg-rs taint witness", "kind": "sink", "origin": "cpg_path"}
            ]
        }))];
        let rows = dataflow_evidence_rows(&events);
        assert_eq!(rows[0].origin, "deep auditor (cpg-rs path)");
    }

    #[test]
    fn model_asserted_guard_citation_gets_code_read_origin() {
        // The model was told to emit kind="guard"; without a cpg_path marker
        // that is a code-read citation, NOT fabricated cpg-rs provenance.
        let events = vec![event(json!({
            "evidence": [
                {"file": "src/users.ts", "start_line": 91, "end_line": 91,
                 "note": "authz gate", "kind": "guard"}
            ]
        }))];
        let rows = dataflow_evidence_rows(&events);
        assert_eq!(rows[0].kind, "guard");
        assert_eq!(rows[0].origin, "deep auditor (code read)");
        // Still labelled as falsifying evidence.
        assert!(rows[0].note.starts_with("falsifying evidence · "));
    }

    #[test]
    fn no_evidence_key_yields_no_rows() {
        assert!(dataflow_evidence_rows(&[event(json!({}))]).is_empty());
    }
}
