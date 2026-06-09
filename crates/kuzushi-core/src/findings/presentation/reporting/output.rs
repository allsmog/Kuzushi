use super::*;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FindingListReport {
    pub count: usize,
    pub findings: Vec<Finding>,
}

impl FindingListReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return "  (no findings match)".to_string();
        }

        finding_list_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        crate::module_result::completed_output_result(self.summary(), self.output(), json!(self))
    }

    fn summary(&self) -> String {
        format!(
            "findings:list: {} matching finding{}",
            self.count,
            plural_suffix(self.count)
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct FindingTableWidths {
    alias: usize,
    fingerprint: usize,
    severity: usize,
    verdict: usize,
    name: usize,
}

fn finding_list_output_lines(report: &FindingListReport) -> Vec<String> {
    let aliased = sorted_finding_aliases(&report.findings);
    let widths = finding_table_widths(&aliased, &report.findings);
    let mut lines = finding_table_header(widths);
    lines.extend(
        aliased
            .iter()
            .map(|(alias, finding)| finding_table_row(alias, finding, widths)),
    );
    lines.push(String::new());
    lines.push(matching_line(report));
    lines
}

fn finding_table_widths(
    aliased: &[(String, Finding)],
    findings: &[Finding],
) -> FindingTableWidths {
    FindingTableWidths {
        alias: max_alias_width(aliased),
        fingerprint: max_fingerprint_width(aliased),
        severity: max_severity_width(findings),
        verdict: max_verdict_width(findings),
        name: max_name_width(findings),
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

fn max_verdict_width(findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| {
            FindingVerdictFilter::from_finding(finding)
                .as_legacy_str()
                .len()
        })
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
            "  {}  {}  {}  {}  {}",
            pad("Alias", widths.alias),
            pad("Fingerprint", widths.fingerprint),
            pad("Sev", widths.severity),
            pad("Check", widths.verdict),
            pad("Name", widths.name)
        ),
        format!(
            "  {}  {}  {}  {}  {}",
            "-".repeat(widths.alias),
            "-".repeat(widths.fingerprint),
            "-".repeat(widths.severity),
            "-".repeat(widths.verdict),
            "-".repeat(widths.name)
        ),
    ]
}

fn finding_table_row(alias: &str, finding: &Finding, widths: FindingTableWidths) -> String {
    format!(
        "  {}  {}  {}  {}  {}",
        pad(alias, widths.alias),
        pad(&short_id(&finding.fingerprint), widths.fingerprint),
        pad(finding.severity.as_str(), widths.severity),
        pad(
            FindingVerdictFilter::from_finding(finding).as_legacy_str(),
            widths.verdict
        ),
        finding.title
    )
}

fn matching_line(report: &FindingListReport) -> String {
    format!("  {} matching (showing {})", report.count, report.findings.len())
}

fn plural_suffix(count: usize) -> &'static str {
    if count != 1 { "s" } else { "" }
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
