use super::*;

impl SecretScanReport {
    pub fn output(&self) -> String {
        let severity_summary = if self.findings.is_empty() {
            "no secrets detected".to_string()
        } else {
            let mut counts = BTreeMap::<&'static str, usize>::new();
            for finding in &self.findings {
                *counts.entry(finding.severity.as_str()).or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(severity, count)| format!("{count} {}", severity.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut lines = vec![
            format!(
                "secret-scan: {} finding{} ({severity_summary})",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" }
            ),
            format!("  Files scanned: {}", self.files_scanned),
            format!("  Files skipped: {}", self.files_skipped),
            format!("  Target:        {}", self.target),
        ];

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }

        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "output": self.output(),
            "data": {
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "target": self.target,
            }
        })
    }
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
        finding.title = self.message.clone();
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
