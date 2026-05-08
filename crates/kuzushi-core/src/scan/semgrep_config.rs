use super::*;

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
        }
    }

    pub fn output(&self) -> String {
        codeql_output_lines(self).join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodeqlPersistedRun {
    pub run_id: String,
    pub findings_db: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_evidence: Option<StaticEvidenceIndexReport>,
}

pub(crate) fn parse_semgrep_config_input(input: &Value) -> Result<Option<Vec<String>>> {
    let Some(raw) = input.get("config").or_else(|| input.get("configFlag")) else {
        return Ok(None);
    };
    Ok(Some(default_semgrep_configs(semgrep_configs_from_value(
        raw,
    )?)))
}

fn codeql_output_lines(report: &CodeqlScanReport) -> Vec<String> {
    let mut lines = vec![codeql_summary_line(report)];
    append_codeql_persisted_run(&mut lines, report.persisted.as_ref());
    append_codeql_top_findings(&mut lines, &report.findings);
    lines
}

fn codeql_summary_line(report: &CodeqlScanReport) -> String {
    format!(
        "codeql: {} finding{} under {}",
        report.count,
        plural_suffix(report.count),
        report.target
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}

fn append_codeql_persisted_run(lines: &mut Vec<String>, persisted: Option<&CodeqlPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
}

fn append_codeql_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(codeql_finding_line));
    append_codeql_remaining_count(lines, findings.len());
}

fn codeql_finding_line(finding: &Finding) -> String {
    format!(
        "  - {} - {} - {}:{}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.file_path,
        finding.start_line
    )
}

fn append_codeql_remaining_count(lines: &mut Vec<String>, finding_count: usize) {
    if finding_count > 10 {
        lines.push(format!("  ... and {} more", finding_count - 10));
    }
}

fn semgrep_configs_from_value(raw: &Value) -> Result<Vec<String>> {
    if let Some(value) = raw.as_str() {
        return Ok(vec![value.trim().to_string()]);
    }
    if let Some(values) = raw.as_array() {
        return values.iter().map(semgrep_config_array_entry).collect();
    }
    anyhow::bail!("semgrep: config/configFlag must be a string or string array")
}

fn semgrep_config_array_entry(value: &Value) -> Result<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
        .context("semgrep: config/configFlag array entries must be non-empty strings")
}

fn default_semgrep_configs(configs: Vec<String>) -> Vec<String> {
    let configs = non_empty_semgrep_configs(configs);
    if configs.is_empty() {
        vec!["auto".to_string()]
    } else {
        configs
    }
}

fn non_empty_semgrep_configs(configs: Vec<String>) -> Vec<String> {
    configs
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect()
}

impl ScanEngine for SemgrepScanner {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }
}
