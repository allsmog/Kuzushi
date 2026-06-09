use super::*;

impl IacScanReport {
    pub fn output(&self) -> String {
        let mut lines = iac_header_lines(self);
        append_iac_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        crate::scan::completed_scan_tool_json(
            self.output(),
            serde_json::json!({
                "count": self.findings.len(),
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "target": self.target,
                "kind": self.kind,
            }),
        )
    }
}

fn iac_header_lines(report: &IacScanReport) -> Vec<String> {
    vec![
        format!(
            "iac-scan: {} finding{} under {}",
            report.findings.len(),
            plural_suffix(report.findings.len()),
            report.target
        ),
        format!("  Files scanned: {}", report.files_scanned),
        format!("  Files skipped: {}", report.files_skipped),
    ]
}

fn append_iac_top_findings(lines: &mut Vec<String>, findings: &[IacScanFinding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(iac_finding_line));
    append_remaining_count(lines, findings.len());
}

fn iac_finding_line(finding: &IacScanFinding) -> String {
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
    if count != 1 { "s" } else { "" }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IacScanFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
    pub manifest_kind: IacScanKind,
}

impl IacScanFinding {
    pub(crate) fn new(
        target: &Path,
        absolute_path: &Path,
        start_line: u32,
        manifest_kind: IacScanKind,
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        let file_path = relative_display(target, absolute_path);
        let message = message.into();
        let evidence = evidence.into();
        let core = Finding::new_tool(
            "iac-scan",
            rule_id.clone(),
            file_path.clone(),
            start_line,
            Some(start_line),
            severity,
            format!("{message}\nEvidence: {evidence}"),
        );

        Self {
            fingerprint: core.fingerprint,
            rule_id,
            file_path,
            start_line,
            severity,
            message,
            evidence,
            manifest_kind,
        }
    }

    pub fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "iac-scan",
            self.rule_id.clone(),
            self.file_path.clone(),
            self.start_line,
            Some(self.start_line),
            self.severity,
            format!("{}\nEvidence: {}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.title = self.message.clone();
        finding.set_static_proof_state(StaticProofState::SignalOnly);
        finding
    }
}
