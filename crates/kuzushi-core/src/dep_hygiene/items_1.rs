use super::prelude::*;
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
            return format!(
                "dep-hygiene: no risky specifiers found under {}.",
                self.target
            );
        }

        let mut lines = vec![
            format!(
                "dep-hygiene: {} risky specifier{} under {}",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                self.target
            ),
            String::new(),
        ];

        for severity in [
            DepHygieneSeverity::High,
            DepHygieneSeverity::Medium,
            DepHygieneSeverity::Low,
        ] {
            let grouped = self
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect::<Vec<_>>();
            if grouped.is_empty() {
                continue;
            }

            lines.push(format!("  [{}]", severity.as_str().to_ascii_uppercase()));
            for finding in grouped {
                let rel = relative_display(Path::new(&self.target), Path::new(&finding.file_path));
                let constraint = if finding.raw_constraint.is_empty() {
                    "(empty)"
                } else {
                    &finding.raw_constraint
                };
                lines.push(format!(
                    "    {rel} :: {}@{} - {}",
                    finding.package_name, constraint, finding.reason
                ));
            }
            lines.push(String::new());
        }

        lines.join("\n").trim_end().to_string()
    }

    pub fn to_tool_json(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "output": self.output(),
            "data": {
                "count": self.count,
                "findings": self.findings,
                "target": self.target,
            }
        })
    }
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
