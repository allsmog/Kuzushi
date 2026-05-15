use super::SeverityCounts;
use crate::ShellApp;
use kuzushi_core::{
    finding_source_label, project_finding, sorted_finding_aliases, stable_finding_alias, Finding,
    Severity,
};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingsModel {
    pub(crate) total: usize,
    pub(crate) triaged: usize,
    pub(crate) pending: usize,
    pub(crate) counts: SeverityCounts,
    pub(crate) header: String,
    pub(crate) cursor: usize,
    pub(crate) empty: FindingsEmptyState,
    pub(crate) rows: Vec<FindingListRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingsEmptyState {
    pub(crate) hint: &'static str,
    pub(crate) context_cta: Option<(&'static str, &'static str)>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingListRow {
    pub(crate) alias: String,
    pub(crate) severity: Severity,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) cwe: String,
    pub(crate) source: String,
    pub(crate) evidence: String,
    pub(crate) selected: bool,
    pub(crate) cursor: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingDetailModel {
    pub(crate) alias: Option<String>,
    pub(crate) severity: Severity,
    pub(crate) severity_label: String,
    pub(crate) title: String,
    pub(crate) location: String,
    pub(crate) rule: String,
    pub(crate) tool: String,
    pub(crate) fingerprint: String,
    pub(crate) proof_state: String,
    pub(crate) runtime_verification: String,
    pub(crate) evidence: Vec<FindingEvidenceRow>,
    pub(crate) message_lines: Vec<String>,
    pub(crate) triage: Option<TriageSummaryModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingEvidenceRow {
    pub(crate) header: String,
    pub(crate) snippet: String,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TriageSummaryModel {
    pub(crate) verdict: String,
    pub(crate) confidence: String,
    pub(crate) rationale: String,
}

pub(crate) fn findings_model(app: &ShellApp) -> FindingsModel {
    let rows = finding_rows(app);
    let total = app.findings.len();
    let triaged = app
        .findings
        .iter()
        .filter(|finding| finding.triage.is_some())
        .count();
    let pending = total.saturating_sub(triaged);
    FindingsModel {
        total,
        triaged,
        pending,
        counts: SeverityCounts::from_findings(&app.findings),
        header: format!("FINDINGS · {total} · {triaged} triaged · {pending} pending"),
        cursor: app.findings_cursor.min(total.saturating_sub(1)),
        empty: empty_state(app.context_view.exists),
        rows,
    }
}

pub(crate) fn selected_finding_detail_model(app: &ShellApp) -> Option<FindingDetailModel> {
    let finding = app.selected_finding.as_ref()?;
    let alias = stable_finding_alias(&app.findings, &finding.fingerprint);
    Some(FindingDetailModel::from_finding(finding, alias))
}

fn finding_rows(app: &ShellApp) -> Vec<FindingListRow> {
    let selected = app
        .selected_finding
        .as_ref()
        .map(|finding| finding.fingerprint.as_str());
    sorted_finding_aliases(&app.findings)
        .into_iter()
        .enumerate()
        .map(|(index, (alias, finding))| {
            FindingListRow::from_finding(index, app.findings_cursor, selected, alias, &finding)
        })
        .collect()
}

fn empty_state(context_exists: bool) -> FindingsEmptyState {
    if context_exists {
        return FindingsEmptyState {
            hint: "scan runs configured scanners against the active target.",
            context_cta: None,
        };
    }
    FindingsEmptyState {
        hint: "scan dispatches the umbrella scanner once context-snapshot exists.",
        context_cta: Some(("context build", "build the snapshot first if you have time")),
    }
}

impl FindingListRow {
    fn from_finding(
        index: usize,
        cursor: usize,
        selected: Option<&str>,
        alias: String,
        finding: &Finding,
    ) -> Self {
        let projection = project_finding(finding, Some(alias.clone()));
        Self {
            alias,
            severity: projection.severity,
            severity_label: projection.severity_label,
            title: projection.title,
            location: projection.location,
            verdict: projection.verdict_label,
            confidence: projection.confidence_label,
            cwe: projection.cwe_label,
            source: finding_source_label(finding),
            evidence: projection.evidence_preview,
            selected: selected.is_some_and(|fingerprint| fingerprint == projection.fingerprint),
            cursor: cursor == index,
        }
    }
}

impl FindingDetailModel {
    fn from_finding(finding: &Finding, alias: Option<String>) -> Self {
        let projection = project_finding(finding, alias);
        Self {
            alias: projection.alias,
            severity: projection.severity,
            severity_label: finding.severity.as_str().to_string(),
            title: projection.title,
            location: projection.location,
            rule: projection.rule,
            tool: projection.tool,
            fingerprint: projection.fingerprint,
            proof_state: projection.proof_state,
            runtime_verification: projection.runtime_validation,
            evidence: evidence_rows(finding),
            message_lines: finding
                .message
                .lines()
                .take(8)
                .map(str::to_string)
                .collect(),
            triage: finding.triage.as_ref().map(TriageSummaryModel::from_triage),
        }
    }
}

impl FindingEvidenceRow {
    fn from_evidence(evidence: &kuzushi_core::FindingEvidence) -> Self {
        Self {
            header: format!(
                "{} · conf {} · {}:{}",
                evidence.kind, evidence.confidence, evidence.file_path, evidence.line
            ),
            snippet: evidence.snippet.clone(),
            rationale: evidence.rationale.clone(),
        }
    }
}

impl TriageSummaryModel {
    fn from_triage(triage: &kuzushi_core::TriageOutcome) -> Self {
        Self {
            verdict: triage.verdict.as_str().to_string(),
            confidence: format!("{:.2}", triage.confidence),
            rationale: triage.rationale.clone(),
        }
    }
}

fn evidence_rows(finding: &Finding) -> Vec<FindingEvidenceRow> {
    finding
        .evidence
        .iter()
        .take(8)
        .map(FindingEvidenceRow::from_evidence)
        .collect()
}

#[cfg(test)]
mod tests;
