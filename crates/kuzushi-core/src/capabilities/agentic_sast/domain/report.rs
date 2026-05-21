use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<AgenticSastPersistedRun>,
    pub cost_usd: f64,
}

impl AgenticSastReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = vec![self.summary()];
        append_persisted_run(&mut lines, self.persisted.as_ref());
        append_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            json!(self),
        );
        output["costUsd"] = json!(self.cost_usd);
        output
    }

    fn summary(&self) -> String {
        format!(
            "agentic-sast: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )
    }
}

fn append_persisted_run(lines: &mut Vec<String>, persisted: Option<&AgenticSastPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}
