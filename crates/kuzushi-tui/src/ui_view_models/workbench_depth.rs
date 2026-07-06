//! View-model for the depth-stack Workbench review surface
//! (`WorkbenchNav`-driven, opt-in via `ui.workbench_depth_stack`).
//!
//! Pure projection over the existing finding / detail / taint-flow view-models,
//! so the depth-stack renderer never re-derives finding data and DETAILS/legs
//! always reflect the authoritative `ShellApp::findings_route`.

use super::{
    findings_model, selected_finding_detail_model, FindingDetailModel, FindingEvidenceRow,
    FindingListRow, SeverityTone,
};
use crate::app::{DrawerTab, NavBounds, ShellApp, WorkbenchNav};

/// Everything the depth stack needs for one frame.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorkbenchModel {
    pub(crate) findings: Vec<FindingRow>,
    /// Index of the cursored finding within `findings` (the app selection).
    pub(crate) selected: usize,
    /// `CWE · severity` header for the data-flow ladder, when a flow exists.
    pub(crate) flow_title: Option<String>,
    pub(crate) legs: Vec<TraceLeg>,
    pub(crate) drawer: DrawerContent,
}

/// One finding row for the list and the compressed spine. Reuses the existing
/// proof-level projection verbatim — no re-derived severity or proof labels.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingRow {
    pub(crate) alias: String,
    pub(crate) severity: SeverityTone,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) proof_label: String,
    pub(crate) proof_marker: &'static str,
    pub(crate) verdict: String,
    pub(crate) confidence: String,
}

/// One leg of the data-flow (trace) path: an edge along source → … → sink.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TraceLeg {
    pub(crate) index: u16,
    pub(crate) from: String,
    pub(crate) to: String,
    pub(crate) kind: LegKind,
    pub(crate) meta: String,
    pub(crate) waypoints: Vec<Waypoint>,
}

/// Where a leg sits on the path. Drives a truthful, domain-native signifier:
/// the tainted source and the dangerous sink are the salient endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegKind {
    Source,
    Hop,
    Sink,
}

/// A propagation node inside one leg (the code at the target stage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Waypoint {
    pub(crate) label: String,
    pub(crate) reached: bool,
}

/// A collapsible record shared by the triage/proof drawers and record zoom.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Stanza {
    pub(crate) id: String,
    pub(crate) state: String,
    pub(crate) state_tone: SeverityTone,
    pub(crate) summary: String,
    pub(crate) body: String,
}

/// The four Depth-1 drawer tabs, projected to render-ready rows.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DrawerContent {
    pub(crate) triage: Vec<Stanza>,
    pub(crate) proof: Vec<Stanza>,
    pub(crate) log: Vec<String>,
    pub(crate) code: Vec<String>,
}

impl DrawerContent {
    pub(crate) fn rows(&self, tab: DrawerTab) -> usize {
        match tab {
            DrawerTab::Triage => self.triage.len(),
            DrawerTab::Proof => self.proof.len(),
            DrawerTab::Log => self.log.len(),
            DrawerTab::Code => self.code.len(),
        }
    }
}

/// Cheap cursor-clamping bounds for the key reducer — skips the full
/// `findings_model` projection (finding *selection* is clamped app-side, so the
/// reducer only needs leg/drawer counts). Called once per keystroke.
pub(crate) fn workbench_depth_bounds(app: &ShellApp, nav: &WorkbenchNav) -> NavBounds {
    let legs = app
        .taint_flow
        .as_ref()
        .map(|flow| flow.stages.len().saturating_sub(1))
        .unwrap_or(0);
    NavBounds {
        legs,
        drawer_rows: drawer_content(app).rows(nav.tab),
    }
}

pub(crate) fn workbench_depth_model(app: &ShellApp) -> WorkbenchModel {
    let findings = findings_model(app);
    let selected = findings.cursor.min(findings.rows.len().saturating_sub(1));
    let rows = findings.rows.iter().map(finding_row).collect();
    let (flow_title, legs) = flow_legs(app);
    WorkbenchModel {
        findings: rows,
        selected,
        flow_title,
        legs,
        drawer: drawer_content(app),
    }
}

fn finding_row(row: &FindingListRow) -> FindingRow {
    FindingRow {
        alias: row.alias.clone(),
        severity: row.severity_tone,
        severity_label: row.severity_label.clone(),
        title: row.title.clone(),
        location: row.location.clone(),
        proof_label: row.proof_label.clone(),
        proof_marker: row.proof_marker,
        verdict: row.verdict.clone(),
        confidence: row.confidence.clone(),
    }
}

fn flow_legs(app: &ShellApp) -> (Option<String>, Vec<TraceLeg>) {
    let Some(flow) = app.taint_flow.as_ref() else {
        return (None, Vec::new());
    };
    let stage_count = flow.stages.len();
    let legs = flow
        .stages
        .windows(2)
        .enumerate()
        .map(|(index, pair)| TraceLeg {
            index: (index + 1) as u16,
            from: stage_label(&pair[0].message, &pair[0].file, pair[0].line),
            to: stage_label(&pair[1].message, &pair[1].file, pair[1].line),
            kind: leg_kind(index, stage_count),
            meta: format!("{}:{}", pair[1].file, pair[1].line),
            waypoints: pair[1]
                .snippet
                .as_ref()
                .map(|snippet| {
                    vec![Waypoint {
                        label: snippet.trim().to_string(),
                        reached: true,
                    }]
                })
                .unwrap_or_default(),
        })
        .collect();
    (Some(format!("{} · {}", flow.cwe, flow.severity)), legs)
}

fn stage_label(message: &str, file: &str, line: u32) -> String {
    if message.trim().is_empty() {
        format!("{file}:{line}")
    } else {
        message.trim().to_string()
    }
}

fn leg_kind(index: usize, stage_count: usize) -> LegKind {
    if index == 0 {
        LegKind::Source
    } else if index + 2 >= stage_count {
        LegKind::Sink
    } else {
        LegKind::Hop
    }
}

fn drawer_content(app: &ShellApp) -> DrawerContent {
    let Some(detail) = selected_finding_detail_model(app) else {
        return DrawerContent::default();
    };
    DrawerContent {
        triage: triage_stanzas(&detail),
        proof: proof_stanzas(&detail),
        log: detail.message_lines.clone(),
        code: code_lines(&detail),
    }
}

fn triage_stanzas(detail: &FindingDetailModel) -> Vec<Stanza> {
    let mut stanzas = Vec::new();
    if let Some(triage) = &detail.triage {
        stanzas.push(Stanza {
            id: "verdict".to_string(),
            state: triage.verdict.clone(),
            state_tone: detail.severity_tone,
            summary: format!("confidence {} · {}", triage.confidence, triage.author),
            body: triage.rationale.clone(),
        });
    }
    for (index, evidence) in detail.evidence.iter().enumerate() {
        stanzas.push(Stanza {
            id: format!("E-{:02}", index + 1),
            state: "EVIDENCE".to_string(),
            state_tone: detail.severity_tone,
            summary: evidence.header.clone(),
            body: evidence_body(evidence),
        });
    }
    stanzas
}

fn evidence_body(evidence: &FindingEvidenceRow) -> String {
    [
        Some(evidence.snippet.as_str()),
        Some(evidence.rationale.as_str()),
        evidence.capture.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("\n")
}

fn proof_stanzas(detail: &FindingDetailModel) -> Vec<Stanza> {
    vec![
        Stanza {
            id: "static".to_string(),
            state: detail.static_proof_label.clone(),
            state_tone: detail.severity_tone,
            summary: detail.proof_label.clone(),
            body: detail.static_proof_explanation.clone(),
        },
        Stanza {
            id: "runtime".to_string(),
            state: detail.runtime_label.clone(),
            state_tone: detail.severity_tone,
            summary: detail.runtime_verification.clone(),
            body: detail.runtime_explanation.clone(),
        },
    ]
}

fn code_lines(detail: &FindingDetailModel) -> Vec<String> {
    let mut lines = vec![detail.location.clone()];
    for evidence in &detail.evidence {
        if !evidence.snippet.trim().is_empty() {
            lines.push(evidence.snippet.clone());
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leg_kind_marks_source_and_sink_endpoints() {
        assert_eq!(leg_kind(0, 4), LegKind::Source);
        assert_eq!(leg_kind(1, 4), LegKind::Hop);
        assert_eq!(leg_kind(2, 4), LegKind::Sink);
        // A two-stage flow is a single source→sink leg; source wins the endpoint.
        assert_eq!(leg_kind(0, 2), LegKind::Source);
    }

    #[test]
    fn stage_label_falls_back_to_location_when_message_blank() {
        assert_eq!(stage_label("  ", "app.rs", 12), "app.rs:12");
        assert_eq!(stage_label(" reaches sink ", "app.rs", 12), "reaches sink");
    }

    #[test]
    fn drawer_rows_counts_the_active_tab() {
        let drawer = DrawerContent {
            triage: vec![],
            proof: vec![],
            log: vec!["a".to_string(), "b".to_string()],
            code: vec![],
        };
        assert_eq!(drawer.rows(DrawerTab::Log), 2);
        assert_eq!(drawer.rows(DrawerTab::Triage), 0);
    }
}
