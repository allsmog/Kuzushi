use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DepHygieneReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<DepHygieneFinding>,
}

impl DepHygieneReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return no_risky_specifiers_line(&self.target);
        }

        dep_hygiene_output_lines(self)
            .join("\n")
            .trim_end()
            .to_string()
    }

    pub fn to_tool_json(&self) -> Value {
        crate::scan::completed_scan_tool_json(
            self.output(),
            serde_json::json!({
                "count": self.count,
                "findings": self.findings,
                "target": self.target,
            }),
        )
    }
}

fn no_risky_specifiers_line(target: &str) -> String {
    format!("dep-hygiene: no risky specifiers found under {target}.")
}

fn dep_hygiene_output_lines(report: &DepHygieneReport) -> Vec<String> {
    let mut lines = vec![risky_specifiers_line(report), String::new()];
    append_severity_groups(&mut lines, report);
    lines
}

fn risky_specifiers_line(report: &DepHygieneReport) -> String {
    format!(
        "dep-hygiene: {} risky specifier{} under {}",
        report.findings.len(),
        plural_suffix(report.findings.len()),
        report.target
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

fn append_severity_groups(lines: &mut Vec<String>, report: &DepHygieneReport) {
    for severity in severity_order() {
        append_severity_group(lines, report, severity);
    }
}

fn severity_order() -> [DepHygieneSeverity; 3] {
    [
        DepHygieneSeverity::High,
        DepHygieneSeverity::Medium,
        DepHygieneSeverity::Low,
    ]
}

fn append_severity_group(
    lines: &mut Vec<String>,
    report: &DepHygieneReport,
    severity: DepHygieneSeverity,
) {
    let grouped = findings_for_severity(&report.findings, severity);
    if grouped.is_empty() {
        return;
    }
    lines.push(format!("  [{}]", severity.as_str().to_ascii_uppercase()));
    lines.extend(
        grouped
            .into_iter()
            .map(|finding| finding_line(report, finding)),
    );
    lines.push(String::new());
}

fn findings_for_severity(
    findings: &[DepHygieneFinding],
    severity: DepHygieneSeverity,
) -> Vec<&DepHygieneFinding> {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .collect()
}

fn finding_line(report: &DepHygieneReport, finding: &DepHygieneFinding) -> String {
    let rel = relative_display(Path::new(&report.target), Path::new(&finding.file_path));
    format!(
        "    {rel} :: {}@{} - {}",
        finding.package_name,
        constraint_display(&finding.raw_constraint),
        finding.reason
    )
}

fn constraint_display(raw_constraint: &str) -> &str {
    if raw_constraint.is_empty() {
        return "(empty)";
    }
    raw_constraint
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DepHygieneFinding {
    pub manifest: String,
    pub file_path: String,
    pub package_name: String,
    pub raw_constraint: String,
    pub severity: DepHygieneSeverity,
    pub reason: String,
}
