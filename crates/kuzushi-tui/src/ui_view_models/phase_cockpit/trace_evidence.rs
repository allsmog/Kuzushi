//! Trace evidence: where does this value travel.
//!
//! The original path is discovery's recorded truth — the finding-keyed
//! taint flow when one exists, else the finding's evidence anchors. The
//! expanded path re-renders from the durable static-evidence store: the
//! hops a `trace:expand` run appended with "requested by operator"
//! provenance. Nothing here infers a hop the agent did not cite.

use super::{TraceEvidenceModel, TraceHopModel};
use crate::ui_view_models::{FindingDetailModel, TaintFlowPath};
use crate::ShellApp;
use kuzushi_core::findings::DataflowEvidenceRow;
use kuzushi_core::Finding;

pub(super) fn trace_evidence_model(
    app: &ShellApp,
    selected: Option<&(Option<String>, Finding)>,
    detail: Option<&FindingDetailModel>,
    attack_path: &TaintFlowPath,
) -> Option<TraceEvidenceModel> {
    if !app.router.workbench().trace_view_open() {
        return None;
    }
    let (alias, finding) = selected?;
    let detail = detail?;
    let expansion = app
        .domain()
        .trace_expansion_for_finding(&finding.fingerprint);
    let expanded: Vec<TraceHopModel> = expansion
        .map(|snapshot| snapshot.steps.iter().map(expanded_hop).collect())
        .unwrap_or_default();
    let open_questions = expansion
        .map(|snapshot| snapshot.open_questions.clone())
        .unwrap_or_default();
    Some(TraceEvidenceModel {
        last_outcome: expansion.and_then(|snapshot| snapshot.last_outcome.clone()),
        identity: super::identity::engagement_identity_line(app),
        reference: alias
            .clone()
            .unwrap_or_else(|| detail.identity_label.clone()),
        severity: detail.severity_label.clone(),
        original: original_hops(finding, attack_path, &detail.dataflow_evidence),
        next_hint: next_hint(&expanded, &open_questions, expansion.is_some()),
        expanded,
        open_questions,
        evidence_deltas: expansion
            .map(|snapshot| snapshot.evidence_deltas.clone())
            .unwrap_or_default(),
        expand_command: format!(
            "run trace:expand {}",
            serde_json::json!({ "fingerprint": finding.fingerprint })
        ),
    })
}

/// The recorded path: the finding-keyed taint flow when discovery emitted
/// one, else the finding's located evidence anchors, else the deep-auditor's
/// cited dataflow rows. Every branch is an agent-cited observation, never
/// synthesis — the third fallback stays honest to that promise.
fn original_hops(
    finding: &Finding,
    attack_path: &TaintFlowPath,
    dataflow: &[DataflowEvidenceRow],
) -> Vec<TraceHopModel> {
    if !attack_path.stages.is_empty() {
        return attack_path.stages.iter().map(stage_hop).collect();
    }
    let anchors: Vec<TraceHopModel> = finding
        .evidence
        .iter()
        .filter(|evidence| !evidence.file_path.is_empty())
        .map(evidence_anchor_hop)
        .collect();
    if !anchors.is_empty() {
        return anchors;
    }
    dataflow.iter().map(dataflow_hop).collect()
}

fn stage_hop(stage: &crate::ui_view_models::TaintStageModel) -> TraceHopModel {
    TraceHopModel {
        label: stage.title.clone(),
        location: stage.location.clone(),
        annotation: stage.snippet.clone().unwrap_or_default(),
    }
}

fn evidence_anchor_hop(evidence: &kuzushi_core::FindingEvidence) -> TraceHopModel {
    TraceHopModel {
        label: evidence.kind.clone(),
        location: format!("{}:{}", evidence.file_path, evidence.line),
        annotation: if evidence.rationale.is_empty() {
            evidence.snippet.clone()
        } else {
            evidence.rationale.clone()
        },
    }
}

/// A guard row surfaces as `guard@file:line` (label `guard`, its location) so
/// the operator sees exactly where the auditor found falsifying evidence.
fn dataflow_hop(row: &DataflowEvidenceRow) -> TraceHopModel {
    TraceHopModel {
        label: row.kind.clone(),
        location: row.location.clone(),
        annotation: row.note.clone(),
    }
}

fn expanded_hop(step: &crate::app::TraceExpansionStep) -> TraceHopModel {
    TraceHopModel {
        label: step.symbol.clone(),
        location: if step.file.is_empty() {
            String::new()
        } else {
            format!("{}:{}", step.file, step.line)
        },
        annotation: step.annotation.clone(),
    }
}

fn next_hint(expanded: &[TraceHopModel], open_questions: &[String], has_outcome: bool) -> String {
    if expanded.is_empty() && !has_outcome {
        "no operator-requested hops yet — draft trace expansion for this finding".to_string()
    } else if open_questions.is_empty() {
        "open an investigation to assess the recorded evidence".to_string()
    } else {
        "resolve the recorded open questions, or open an investigation".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::TaintStageModel;
    use kuzushi_core::{FindingEvidence, Severity};

    fn finding_with_evidence() -> Finding {
        let mut finding = Finding::new_semgrep(
            "demo.trace",
            "src/parse.rs",
            10,
            None,
            Severity::High,
            "length flows to memcpy",
        );
        finding.evidence = vec![
            FindingEvidence {
                kind: "source".to_string(),
                file_path: "src/input.rs".to_string(),
                line: 4,
                snippet: "read(buf)".to_string(),
                rationale: "attacker-controlled read".to_string(),
                confidence: 80,
                ..Default::default()
            },
            FindingEvidence {
                kind: "sink".to_string(),
                ..Default::default()
            },
        ];
        finding
    }

    #[test]
    fn original_path_prefers_the_finding_keyed_taint_flow() {
        let path = TaintFlowPath {
            stages: vec![TaintStageModel {
                title: "source".to_string(),
                location: "src/input.rs:4".to_string(),
                snippet: Some("read(buf)".to_string()),
            }],
            ..Default::default()
        };
        let hops = original_hops(&finding_with_evidence(), &path, &[]);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].location, "src/input.rs:4");
        assert_eq!(hops[0].annotation, "read(buf)");
    }

    #[test]
    fn original_path_falls_back_to_located_evidence_anchors() {
        let hops = original_hops(&finding_with_evidence(), &TaintFlowPath::default(), &[]);
        assert_eq!(hops.len(), 1, "anchor without a file path is dropped");
        assert_eq!(hops[0].label, "source");
        assert_eq!(hops[0].location, "src/input.rs:4");
        assert_eq!(hops[0].annotation, "attacker-controlled read");
    }

    fn guard_dataflow_row() -> DataflowEvidenceRow {
        DataflowEvidenceRow {
            origin: "deep auditor (cpg-rs path)".to_string(),
            location: "src/users.ts:91".to_string(),
            kind: "guard".to_string(),
            note: "falsifying evidence · authz gate".to_string(),
        }
    }

    fn finding_without_located_evidence() -> Finding {
        Finding::new_semgrep(
            "demo.trace",
            "src/parse.rs",
            10,
            None,
            Severity::High,
            "length flows to memcpy",
        )
    }

    #[test]
    fn dataflow_rows_are_the_third_fallback_and_surface_the_guard() {
        let dataflow = vec![guard_dataflow_row()];
        let hops = original_hops(
            &finding_without_located_evidence(),
            &TaintFlowPath::default(),
            &dataflow,
        );
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].label, "guard");
        assert_eq!(hops[0].location, "src/users.ts:91");
        // The hop identifies guard@file:line — where the auditor cited
        // falsifying evidence.
        assert_eq!(
            format!("{}@{}", hops[0].label, hops[0].location),
            "guard@src/users.ts:91"
        );
        assert_eq!(hops[0].annotation, "falsifying evidence · authz gate");
    }

    #[test]
    fn located_finding_evidence_wins_over_dataflow_rows() {
        let dataflow = vec![guard_dataflow_row()];
        let hops = original_hops(
            &finding_with_evidence(),
            &TaintFlowPath::default(),
            &dataflow,
        );
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].label, "source");
        assert_eq!(hops[0].location, "src/input.rs:4");
    }

    #[test]
    fn next_hint_tracks_expansion_state() {
        assert!(next_hint(&[], &[], false).contains("draft trace expansion"));
        let hop = TraceHopModel {
            label: "f".to_string(),
            location: "a:1".to_string(),
            annotation: String::new(),
        };
        assert!(next_hint(std::slice::from_ref(&hop), &[], true).contains("open an investigation"));
        assert!(next_hint(&[hop], &["role unknown".to_string()], true).contains("open questions"));
    }
}
