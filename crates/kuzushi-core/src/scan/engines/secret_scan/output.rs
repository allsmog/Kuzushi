use super::*;

impl SecretScanReport {
    pub fn output(&self) -> String {
        let mut lines = secret_scan_header_lines(self);
        append_secret_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        crate::scan::scan_tool_json_with_coverage(
            self.output(),
            serde_json::json!({
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "coverageGaps": self.coverage_gaps,
                "target": self.target,
                "inspection": self.inspection,
            }),
            &self.coverage_gaps.scan_error_lines(),
        )
    }
}

fn secret_scan_header_lines(report: &SecretScanReport) -> Vec<String> {
    let mut lines = vec![
        format!(
            "secret-scan: {} finding{} ({})",
            report.findings.len(),
            plural_suffix(report.findings.len()),
            severity_summary(&report.findings)
        ),
        format!("  Files scanned: {}", report.files_scanned),
        format!("  Files skipped: {}", report.files_skipped),
        format!("  Target:        {}", report.target),
    ];
    lines.extend(inspection_lines(report.inspection.as_ref()));
    lines.extend(report.coverage_gaps.disclosure_lines());
    lines
}

fn inspection_lines(inspection: Option<&SecretScanInspection>) -> Vec<String> {
    let Some(inspection) = inspection else {
        return Vec::new();
    };
    let entries = inspection
        .traversal_entries
        .map_or("exact file membership".into(), |count| {
            format!("{count} / {} entries", inspection.max_entries)
        });
    vec![
        format!("  Inspection: {entries}"),
        format!(
            "  Content read reservations: {} / {} bytes",
            inspection.content_bytes_reserved, inspection.max_total_bytes
        ),
        format!(
            "  Limits: {} bytes/file · {} findings; reaching a limit leaves coverage incomplete",
            inspection.max_file_bytes, inspection.max_findings
        ),
        format!("  Excluded directory names: {}", inspection.excluded_directories.join(", ")),
        format!("  Excluded file extensions: {}", inspection.excluded_extensions.join(", ")),
        "  Symlinks and binary content are excluded. Matching strings are signals; credential validity is not checked.".into(),
    ]
}

fn severity_summary(findings: &[SecretScanFinding]) -> String {
    if findings.is_empty() {
        return "no secrets detected".to_string();
    }
    severity_counts(findings)
        .into_iter()
        .map(|(severity, count)| format!("{count} {}", severity.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn severity_counts(findings: &[SecretScanFinding]) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.severity.as_str()).or_default() += 1;
    }
    counts
}

fn append_secret_top_findings(lines: &mut Vec<String>, findings: &[SecretScanFinding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(secret_finding_line));
    append_remaining_count(lines, findings.len());
}

fn secret_finding_line(finding: &SecretScanFinding) -> String {
    format!(
        "  - {} - {} - {}:{}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.file_path,
        finding.start_line
    )
}

fn append_remaining_count(lines: &mut Vec<String>, finding_count: usize) {
    if finding_count > 10 {
        lines.push(format!("  ... and {} more", finding_count - 10));
    }
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanFinding {
    pub task_id: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: SecretSeverity,
    pub message: String,
    pub evidence: String,
    pub scanner_confidence: String,
    pub subcategory: Vec<String>,
    pub likelihood: String,
    pub impact: String,
    pub cwe: Vec<String>,
    pub score: u32,
    /// Line-independent occurrence key (`secret:<detector>:<value hash>#<n>`)
    /// that keeps repeated copies of one secret in a file distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

impl SecretScanFinding {
    pub(crate) fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "secret-scan",
            self.rule_id.clone(),
            self.file_path.clone(),
            self.start_line,
            None,
            self.severity.to_core_severity(),
            format!("{}\n{}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.symbol_locator = self.locator.clone();
        finding.title = self.message.clone();
        finding.set_static_proof_state(StaticProofState::SignalOnly);
        finding
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretSeverity {
    Error,
    Warning,
    Info,
}
