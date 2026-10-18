use super::*;

const TOOL_JSON_MESSAGE_LIMIT: usize = 1_000;
const TOOL_JSON_EVIDENCE_LIMIT: usize = 3;
const TOOL_JSON_EVIDENCE_TEXT_LIMIT: usize = 300;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FindingListReport {
    pub count: usize,
    pub findings: Vec<Finding>,
    /// Ledger-stable alias per row, parallel to `findings`. Aliases are
    /// positional over the sorted WHOLE ledger, so a filtered or clamped
    /// subset must carry them from the store — recomputing over the subset
    /// can assign the same alias to a different finding than `kz finding`
    /// resolves. Empty means the constructor had no whole-ledger view and
    /// display falls back to subset-positional aliases.
    pub aliases: Vec<String>,
    /// Current decisions keyed by fingerprint, separate from scanner-authored triage.
    #[serde(skip)]
    pub review_decisions: std::collections::BTreeMap<String, ReviewDecision>,
}

impl FindingListReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return "  (no findings match)".to_string();
        }

        finding_list_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            self.aliased_rows_json(),
        )
    }

    /// The aliased machine-readable rows without the tool-result envelope —
    /// the one serialization the CLI `--json` flag and the tool data share.
    pub fn aliased_rows_json(&self) -> Value {
        json!(FindingListToolData::from_report(self))
    }

    fn review_decision(&self, finding: &Finding) -> Option<&ReviewDecision> {
        self.review_decisions.get(&finding.fingerprint)
    }

    fn verdict(&self, finding: &Finding) -> FindingVerdictFilter {
        self.review_decision(finding)
            .map(|decision| FindingVerdictFilter::from_review_decision(decision.verdict))
            .unwrap_or_else(|| FindingVerdictFilter::from_finding(finding))
    }

    fn aliased_rows(&self) -> Vec<(String, Finding)> {
        if self.aliases.len() != self.findings.len() {
            return sorted_finding_aliases(&self.findings);
        }
        let mut rows: Vec<(String, Finding)> = self
            .aliases
            .iter()
            .cloned()
            .zip(self.findings.iter().cloned())
            .collect();
        // Ledger alias order IS (severity, fingerprint) order, so this keeps
        // the table sorted while preserving the carried aliases.
        rows.sort_by(|a, b| {
            severity_rank(a.1.severity)
                .cmp(&severity_rank(b.1.severity))
                .then_with(|| a.1.fingerprint.cmp(&b.1.fingerprint))
        });
        rows
    }

    fn ordered_aliased_rows(
        &self,
        order: crate::findings::FindingPageOrder,
    ) -> Vec<(String, Finding)> {
        let mut rows = self.aliased_rows();
        if order == crate::findings::FindingPageOrder::Confidence {
            rows.sort_by(|(_, left), (_, right)| {
                crate::findings::compare_findings_by_confidence(left, right)
            });
        }
        rows
    }

    fn summary(&self) -> String {
        format!(
            "findings:list: {} matching finding{}",
            self.count,
            plural_suffix(self.count)
        )
    }
}

impl crate::findings::FindingListPage {
    pub fn to_tool_json(&self) -> Value {
        let rows = self.report.ordered_aliased_rows(self.page.order);
        let data = FindingListToolData::from_rows(&self.report, &rows);
        let mut data = json!(data);
        data["page"] = json!(self.page);
        let mut lines = finding_list_output_for_rows(&self.report, rows);
        lines.push(format!(
            "Page: {} loaded, starting at {} of {} matching",
            self.page.loaded, self.page.offset, self.page.total
        ));
        if let Some(scope) = &self.page.scope_filter {
            lines.push(scope.output());
        }
        crate::module_result::completed_output_result(self.report.summary(), lines.join("\n"), data)
    }
}

impl crate::findings::FindingScopeFilterReceipt {
    pub fn output(&self) -> String {
        let mut lines = vec![format!("Scope history: {} matching recorded runs; {} unbound; {} unavailable. Findings are current ledger identities with matching historical observations.", self.matched_runs, self.unbound_runs, self.unavailable_runs.len())];
        for reference in &self.references {
            lines.push(format!(
                "Scope {}: {} r{} · record {}",
                reference.scope_id,
                reference.proposal.proposal_id,
                reference.proposal.revision,
                reference.proposal.record_hash
            ));
        }
        if !self.unavailable_runs.is_empty() {
            lines.push(format!("Scope metadata unavailable for: {}. Counts describe readable matching history only.", self.unavailable_runs.join(", ")));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingListToolData {
    count: usize,
    findings: Vec<FindingListToolFinding>,
}

impl FindingListToolData {
    fn from_report(report: &FindingListReport) -> Self {
        Self::from_rows(report, &report.aliased_rows())
    }

    fn from_rows(report: &FindingListReport, rows: &[(String, Finding)]) -> Self {
        Self {
            count: report.count,
            findings: rows
                .iter()
                .map(|(alias, finding)| {
                    FindingListToolFinding::from_finding(
                        alias,
                        finding,
                        report.review_decision(finding),
                    )
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct FindingListToolFinding {
    alias: String,
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: String,
    file_path: String,
    start_line: u32,
    end_line: Option<u32>,
    message: String,
    tool: String,
    static_proof_state: Option<String>,
    proof_confidence: String,
    suppressed: bool,
    review_decision: Option<String>,
    review_decision_author: Option<TriageAuthor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation_gap: Option<crate::findings::FindingObservationGap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation_note: Option<String>,
    triaged_by: Option<TriageAuthor>,
    source_signature: Option<String>,
    corroboration_count: u32,
    sources: Vec<FindingSource>,
    triage: Option<TriageOutcome>,
    verification: Option<PersistedVerification>,
    evidence: Vec<FindingListToolEvidence>,
}

impl FindingListToolFinding {
    fn from_finding(alias: &str, finding: &Finding, review: Option<&ReviewDecision>) -> Self {
        Self {
            alias: alias.to_string(),
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            severity: finding.severity.as_str().to_string(),
            file_path: finding.file_path.clone(),
            start_line: finding.start_line,
            end_line: finding.end_line,
            message: cap_tool_json_text(&finding.message, TOOL_JSON_MESSAGE_LIMIT),
            tool: finding.tool.clone(),
            static_proof_state: finding
                .static_proof_state
                .map(|state| state.as_str().to_string()),
            proof_confidence: ProofConfidence::classify(finding).as_str().to_string(),
            suppressed: finding.suppressed,
            review_decision: review
                .map(|decision| decision.verdict.as_str().to_string())
                .or_else(|| review_decision_label(finding)),
            review_decision_author: review
                .map(|decision| decision.author)
                .or(finding.triaged_by),
            observation_gap: finding.observation_gap.clone(),
            observation_note: crate::findings::observation_gap_note(finding),
            triaged_by: finding.triaged_by,
            source_signature: finding.source_signature.clone(),
            corroboration_count: finding.corroboration_count,
            sources: finding.sources.clone(),
            triage: finding.triage.clone(),
            verification: finding.verification.clone(),
            evidence: finding
                .evidence
                .iter()
                .take(TOOL_JSON_EVIDENCE_LIMIT)
                .map(FindingListToolEvidence::from_evidence)
                .collect(),
        }
    }
}

fn review_decision_label(finding: &Finding) -> Option<String> {
    let triage = finding.triage.as_ref()?;
    Some(
        ReviewDecision::from_triage(triage, finding.triaged_by)
            .verdict
            .as_str()
            .to_string(),
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingListToolEvidence {
    kind: String,
    file_path: String,
    line: u32,
    snippet: String,
    rationale: String,
    confidence: u8,
    request_blob_present: bool,
    response_blob_present: bool,
}

impl FindingListToolEvidence {
    fn from_evidence(evidence: &FindingEvidence) -> Self {
        Self {
            kind: evidence.kind.clone(),
            file_path: evidence.file_path.clone(),
            line: evidence.line,
            snippet: cap_tool_json_text(&evidence.snippet, TOOL_JSON_EVIDENCE_TEXT_LIMIT),
            rationale: cap_tool_json_text(&evidence.rationale, TOOL_JSON_EVIDENCE_TEXT_LIMIT),
            confidence: evidence.confidence,
            request_blob_present: evidence.request_blob.is_some(),
            response_blob_present: evidence.response_blob.is_some(),
        }
    }
}

fn cap_tool_json_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut capped = value.chars().take(max_chars).collect::<String>();
    capped.push_str("...");
    capped
}

#[derive(Debug, Clone, Copy)]
struct FindingTableWidths {
    alias: usize,
    fingerprint: usize,
    severity: usize,
    confidence: usize,
    verdict: usize,
    name: usize,
}

fn finding_list_output_lines(report: &FindingListReport) -> Vec<String> {
    finding_list_output_for_rows(report, report.aliased_rows())
}

fn finding_list_output_for_rows(
    report: &FindingListReport,
    aliased: Vec<(String, Finding)>,
) -> Vec<String> {
    let widths = finding_table_widths(&aliased, report);
    let mut lines = finding_table_header(widths);
    lines.extend(aliased.iter().map(|(alias, finding)| {
        finding_table_row(alias, finding, report.verdict(finding), widths)
    }));
    lines.push(String::new());
    lines.push(matching_line(report));
    lines.extend(aliased.iter().filter_map(|(alias, finding)| {
        crate::findings::observation_gap_note(finding).map(|note| format!("{alias}: {note}"))
    }));
    lines
}

fn finding_table_widths(
    aliased: &[(String, Finding)],
    report: &FindingListReport,
) -> FindingTableWidths {
    FindingTableWidths {
        alias: max_alias_width(aliased),
        fingerprint: max_fingerprint_width(aliased),
        severity: max_severity_width(&report.findings),
        confidence: "unverified".len(),
        verdict: max_verdict_width(report),
        name: max_name_width(&report.findings),
    }
}

fn max_alias_width(aliased: &[(String, Finding)]) -> usize {
    aliased
        .iter()
        .map(|(alias, _)| alias.len())
        .max()
        .unwrap_or(5)
        .max(5)
}

fn max_fingerprint_width(aliased: &[(String, Finding)]) -> usize {
    aliased
        .iter()
        .map(|(_, finding)| short_id(&finding.fingerprint).len())
        .max()
        .unwrap_or(8)
        .max(8)
}

fn max_severity_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| finding.severity.as_str().len())
        .max()
        .unwrap_or(4)
        .max(4)
}

fn max_verdict_width(report: &FindingListReport) -> usize {
    report
        .findings
        .iter()
        .map(|finding| report.verdict(finding).as_export_str().len())
        .max()
        .unwrap_or(5)
        .max(5)
}

fn max_name_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| finding.title.len())
        .max()
        .unwrap_or(4)
        .max(4)
}

fn finding_table_header(widths: FindingTableWidths) -> Vec<String> {
    vec![
        format!(
            "  {}  {}  {}  {}  {}  {}",
            pad("Alias", widths.alias),
            pad("Fingerprint", widths.fingerprint),
            pad("Sev", widths.severity),
            pad("Conf", widths.confidence),
            pad("Check", widths.verdict),
            pad("Name", widths.name)
        ),
        format!(
            "  {}  {}  {}  {}  {}  {}",
            "-".repeat(widths.alias),
            "-".repeat(widths.fingerprint),
            "-".repeat(widths.severity),
            "-".repeat(widths.confidence),
            "-".repeat(widths.verdict),
            "-".repeat(widths.name)
        ),
    ]
}

fn finding_table_row(
    alias: &str,
    finding: &Finding,
    verdict: FindingVerdictFilter,
    widths: FindingTableWidths,
) -> String {
    format!(
        "  {}  {}  {}  {}  {}  {}",
        pad(alias, widths.alias),
        pad(&short_id(&finding.fingerprint), widths.fingerprint),
        pad(finding.severity.as_str(), widths.severity),
        pad(
            ProofConfidence::classify(finding).as_str(),
            widths.confidence
        ),
        pad(verdict.as_export_str(), widths.verdict),
        finding.title
    )
}

fn matching_line(report: &FindingListReport) -> String {
    format!(
        "  {} matching (showing {})",
        report.count,
        report.findings.len()
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

pub fn format_finding_alias(index: usize) -> String {
    format!("F-{:04}", index + 1)
}

pub fn parse_finding_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("F-")
        .or_else(|| reference.strip_prefix("f-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}
