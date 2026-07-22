//! Prove-phase selection and verdict decoding for `fuzz:prove`.
//!
//! The engine's `finding-impact` verb replays one verified finding's PoV
//! (ASAN primitive parse, UBSan wrap replay, flag-profile matrix, adjacency
//! leads) and appends an `impact` row to the findings index, which the
//! import fold turns into impact-derived severity. This module owns the pure
//! parts — which findings deserve a pass and what the engine payload said;
//! subprocess execution stays in the module layer.

use super::index_rows::{write_evidence_flag, FoldedFinding};
use serde_json::{json, Value};

/// Narrowing filters for the impact pass.
#[derive(Debug, Default)]
pub struct ProveFilter {
    pub target: Option<String>,
    pub run_id: Option<String>,
    pub finding_id: Option<String>,
}

/// One finding selected for the impact pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveCandidate {
    pub finding_id: String,
    pub run_id: String,
    pub target: String,
}

/// Verified findings without an impact verdict, in index order. An explicit
/// `finding_id` re-grades even an already-impacted finding (the pass is a
/// deterministic replay, so re-running is safe); without one, existing
/// verdicts are final.
pub fn select_candidates(
    folded: &[FoldedFinding],
    filter: &ProveFilter,
    max: usize,
) -> Vec<ProveCandidate> {
    folded
        .iter()
        .filter(|row| row_matches(row, filter))
        .take(max)
        .map(|row| ProveCandidate {
            finding_id: row.recorded.finding_id.clone(),
            run_id: row.recorded.run_id.clone(),
            target: row.recorded.target.clone(),
        })
        .collect()
}

fn row_matches(row: &FoldedFinding, filter: &ProveFilter) -> bool {
    if !row.recorded.verified || row.recorded.run_id.is_empty() {
        return false;
    }
    if let Some(finding_id) = filter.finding_id.as_deref() {
        return row.recorded.finding_id == finding_id;
    }
    if row.impact_primitive.is_some() {
        return false;
    }
    if let Some(run_id) = filter.run_id.as_deref() {
        if row.recorded.run_id != run_id {
            return false;
        }
    }
    filter
        .target
        .as_deref()
        .is_none_or(|target| target_matches(&row.recorded.target, target))
}

/// The engine records `target` either as the bare name or in project-path
/// form (`localfuzz/c/<name>`); a filter must match both spellings.
fn target_matches(recorded: &str, filter: &str) -> bool {
    recorded == filter || recorded.ends_with(&format!("/{filter}"))
}

/// Flatten the engine's `finding-impact` payload into the verdict row the
/// tool reports. The payload carries the impact block under `"impact"`.
pub fn verdict_from_payload(candidate: &ProveCandidate, payload: &Value) -> Value {
    let impact = payload.get("impact").cloned().unwrap_or(Value::Null);
    json!({
        "findingId": candidate.finding_id,
        "runId": candidate.run_id,
        "target": candidate.target,
        "primitive": impact.get("primitive").cloned().unwrap_or(Value::Null),
        "writeEvidence": impact.get("write_evidence").cloned().unwrap_or(Value::Null),
        "notes": impact.get("notes").cloned().unwrap_or_else(|| json!([])),
        "flagMatrix": impact.get("flag_matrix").cloned().unwrap_or(Value::Null),
        "leads": impact.get("leads").cloned().unwrap_or_else(|| json!([])),
    })
}

/// A verdict is write-class when the replay proved a write/exec primitive or
/// the write oracle produced non-`"none"` evidence.
pub fn verdict_is_write_class(verdict: &Value) -> bool {
    let primitive = verdict.get("primitive").and_then(Value::as_str);
    if matches!(primitive, Some("write") | Some("exec")) {
        return true;
    }
    verdict
        .get("writeEvidence")
        .is_some_and(write_evidence_flag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::fuzz_engine::index_rows::parse_and_fold;

    fn folded_fixture() -> Vec<FoldedFinding> {
        let body = [
            r#"{"event":"recorded","finding_id":"finding-aa","run_id":"run-1","target":"localfuzz/c/tsk_bdi","verified":true}"#,
            r#"{"event":"recorded","finding_id":"finding-bb","run_id":"run-1","target":"localfuzz/c/tsk_bdi","verified":true}"#,
            r#"{"event":"impact","finding_id":"finding-bb","detail":{"primitive":"read","write_evidence":"none"}}"#,
            r#"{"event":"recorded","finding_id":"finding-cc","run_id":"run-2","target":"localfuzz/c/yara_scan","verified":true}"#,
            r#"{"event":"recorded","finding_id":"finding-dd","run_id":"run-2","target":"localfuzz/c/yara_scan","verified":false}"#,
        ]
        .join("\n");
        parse_and_fold(&body).0
    }

    #[test]
    fn selects_verified_unimpacted_findings_and_honors_filters() {
        let folded = folded_fixture();

        let all = select_candidates(&folded, &ProveFilter::default(), 10);
        assert_eq!(
            all.iter().map(|c| c.finding_id.as_str()).collect::<Vec<_>>(),
            vec!["finding-aa", "finding-cc"],
            "already-impacted and unverified rows are excluded"
        );

        let by_target = select_candidates(
            &folded,
            &ProveFilter { target: Some("yara_scan".into()), ..Default::default() },
            10,
        );
        assert_eq!(by_target.len(), 1);
        assert_eq!(by_target[0].finding_id, "finding-cc");

        let by_run = select_candidates(
            &folded,
            &ProveFilter { run_id: Some("run-1".into()), ..Default::default() },
            10,
        );
        assert_eq!(by_run.len(), 1);
        assert_eq!(by_run[0].finding_id, "finding-aa");

        assert_eq!(select_candidates(&folded, &ProveFilter::default(), 1).len(), 1);
    }

    #[test]
    fn explicit_finding_id_regrades_an_already_impacted_finding() {
        let folded = folded_fixture();
        let filter = ProveFilter { finding_id: Some("finding-bb".into()), ..Default::default() };

        let selected = select_candidates(&folded, &filter, 10);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].finding_id, "finding-bb");
        assert_eq!(selected[0].run_id, "run-1");
    }

    #[test]
    fn verdict_flattens_the_impact_block_and_classifies_writes() {
        let candidate = ProveCandidate {
            finding_id: "finding-aa".into(),
            run_id: "run-1".into(),
            target: "localfuzz/c/tsk_bdi".into(),
        };
        let payload = json!({
            "ok": true,
            "impact": {
                "primitive": "read",
                "write_evidence": "valgrind Invalid write of size 8",
                "notes": ["escalates"],
            },
        });

        let verdict = verdict_from_payload(&candidate, &payload);

        assert_eq!(verdict["findingId"], json!("finding-aa"));
        assert_eq!(verdict["primitive"], json!("read"));
        assert!(verdict_is_write_class(&verdict), "positive oracle evidence is write-class");

        let read_only = verdict_from_payload(
            &candidate,
            &json!({"impact": {"primitive": "read", "write_evidence": "none"}}),
        );
        assert!(!verdict_is_write_class(&read_only));

        let exec = verdict_from_payload(&candidate, &json!({"impact": {"primitive": "exec"}}));
        assert!(verdict_is_write_class(&exec));
    }
}
