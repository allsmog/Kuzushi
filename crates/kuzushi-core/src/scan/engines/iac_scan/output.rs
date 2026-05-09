use super::*;

impl IacScanReport {
    pub fn output(&self) -> String {
        let mut lines = vec![
            format!(
                "iac-scan: {} finding{} under {}",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                self.target
            ),
            format!("  Files scanned: {}", self.files_scanned),
            format!("  Files skipped: {}", self.files_skipped),
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
                "count": self.findings.len(),
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "target": self.target,
                "kind": self.kind,
            }
        })
    }
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
        finding
    }
}
