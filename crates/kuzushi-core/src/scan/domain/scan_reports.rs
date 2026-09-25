use super::*;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepScanReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<SemgrepPersistedRun>,
    /// Semgrep-reported scan errors (skipped files/rules). Non-empty means
    /// the run completed with incomplete coverage, and the report says so.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scan_errors: Vec<String>,
}

impl SemgrepScanReport {
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        persisted: Option<SemgrepPersistedRun>,
    ) -> Self {
        Self {
            target: target.into(),
            count: findings.len(),
            findings,
            persisted,
            scan_errors: Vec::new(),
        }
    }

    pub fn with_scan_errors(mut self, scan_errors: Vec<String>) -> Self {
        self.scan_errors = scan_errors;
        self
    }

    pub fn output(&self) -> String {
        semgrep_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        completed_scan_tool_json(self.output(), json!(self))
    }
}

fn semgrep_output_lines(report: &SemgrepScanReport) -> Vec<String> {
    let mut lines = vec![semgrep_summary_line(report)];
    append_semgrep_persisted_run(&mut lines, report.persisted.as_ref());
    append_scan_errors(
        &mut lines,
        "  Semgrep skipped some files or rules:",
        &report.scan_errors,
    );
    append_top_findings(&mut lines, &report.findings);
    lines
}

fn semgrep_summary_line(report: &SemgrepScanReport) -> String {
    format!(
        "semgrep: {} finding{} under {}{}",
        report.count,
        plural_suffix(report.count),
        report.target,
        coverage_note(&report.scan_errors)
    )
}

const MAX_LISTED_SCAN_ERRORS: usize = 3;

/// The summary-line suffix that keeps a partial scan from reading as a full
/// one. Empty when the engine covered everything it was asked to.
fn coverage_note(scan_errors: &[String]) -> String {
    if scan_errors.is_empty() {
        return String::new();
    }
    format!(
        " (coverage incomplete: {} scan error{})",
        scan_errors.len(),
        plural_suffix(scan_errors.len())
    )
}

fn append_scan_errors(lines: &mut Vec<String>, header: &str, scan_errors: &[String]) {
    if scan_errors.is_empty() {
        return;
    }
    lines.push(header.to_string());
    lines.extend(
        scan_errors
            .iter()
            .take(MAX_LISTED_SCAN_ERRORS)
            .map(|entry| format!("  ! {entry}")),
    );
    if scan_errors.len() > MAX_LISTED_SCAN_ERRORS {
        lines.push(format!(
            "  ... and {} more scan errors",
            scan_errors.len() - MAX_LISTED_SCAN_ERRORS
        ));
    }
}

fn append_semgrep_persisted_run(lines: &mut Vec<String>, persisted: Option<&SemgrepPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(persisted_run_line(
            &persisted.run_id,
            &persisted.findings_db,
        ));
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemgrepPersistedRun {
    pub run_id: String,
    pub findings_db: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_evidence: Option<StaticEvidenceIndexReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlScanReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<CodeqlPersistedRun>,
    #[serde(rename = "reportSarif", skip_serializing_if = "Option::is_none")]
    pub report_sarif: Option<Value>,
    /// Detected languages CodeQL could not analyze, and SARIF results a
    /// completed analysis produced but normalization could not represent.
    /// Non-empty means the run completed with incomplete coverage, and the
    /// report says so.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scan_errors: Vec<String>,
}

impl CodeqlScanReport {
    pub fn new(
        target: impl Into<String>,
        findings: Vec<Finding>,
        persisted: Option<CodeqlPersistedRun>,
    ) -> Self {
        Self {
            target: target.into(),
            count: findings.len(),
            findings,
            persisted,
            report_sarif: None,
            scan_errors: Vec::new(),
        }
    }

    pub fn with_sarif_documents(mut self, documents: Vec<String>) -> Self {
        self.report_sarif = sarif_report_value(documents);
        self
    }

    pub fn with_scan_errors(mut self, scan_errors: Vec<String>) -> Self {
        self.scan_errors = scan_errors;
        self
    }

    pub fn output(&self) -> String {
        codeql_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        completed_scan_tool_json(self.output(), json!(self))
    }
}

fn sarif_report_value(documents: Vec<String>) -> Option<Value> {
    let mut values = documents
        .into_iter()
        .filter_map(|document| serde_json::from_str::<Value>(&document).ok())
        .collect::<Vec<_>>();
    if values.len() == 1 {
        return values.pop();
    }
    merged_sarif_report(values)
}

fn merged_sarif_report(values: Vec<Value>) -> Option<Value> {
    let runs = values
        .iter()
        .filter_map(|value| value.get("runs").and_then(Value::as_array))
        .flat_map(|runs| runs.iter().cloned())
        .collect::<Vec<_>>();
    if runs.is_empty() {
        return None;
    }
    Some(json!({
        "version": sarif_version(&values),
        "runs": runs,
    }))
}

fn sarif_version(values: &[Value]) -> String {
    values
        .iter()
        .filter_map(|value| value.get("version").and_then(Value::as_str))
        .next()
        .unwrap_or("2.1.0")
        .to_string()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlPersistedRun {
    pub run_id: String,
    pub findings_db: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_evidence: Option<StaticEvidenceIndexReport>,
}

/// Covers both gap kinds: a detected language whose analysis failed, and a
/// completed analysis whose SARIF results could not be represented. Each
/// entry names its own cause.
const CODEQL_COVERAGE_GAP_HEADER: &str =
    "  CodeQL coverage is incomplete (languages not analyzed or SARIF results omitted):";

fn codeql_output_lines(report: &CodeqlScanReport) -> Vec<String> {
    let mut lines = vec![codeql_summary_line(report)];
    append_codeql_persisted_run(&mut lines, report.persisted.as_ref());
    append_scan_errors(
        &mut lines,
        CODEQL_COVERAGE_GAP_HEADER,
        &report.scan_errors,
    );
    append_codeql_top_findings(&mut lines, &report.findings);
    lines
}

fn codeql_summary_line(report: &CodeqlScanReport) -> String {
    format!(
        "codeql: {} finding{} under {}{}",
        report.count,
        plural_suffix(report.count),
        report.target,
        coverage_note(&report.scan_errors)
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

fn append_codeql_persisted_run(lines: &mut Vec<String>, persisted: Option<&CodeqlPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(persisted_run_line(
            &persisted.run_id,
            &persisted.findings_db,
        ));
    }
}

fn append_codeql_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    append_top_findings(lines, findings);
}

fn persisted_run_line(run_id: &str, findings_db: &str) -> String {
    format!("  Persisted run: {run_id} ({findings_db})")
}

fn append_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(finding_line));
    append_remaining_count(lines, findings.len());
}

fn finding_line(finding: &Finding) -> String {
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
