use super::prelude::*;
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
        let mut lines = vec![format!(
            "codeql: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];

        if let Some(persisted) = &self.persisted {
            lines.push(format!(
                "  Persisted run: {} ({})",
                persisted.run_id, persisted.findings_db
            ));
        }

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

    let configs = match raw {
        Value::String(value) => vec![value.trim().to_string()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .map(ToString::to_string)
                    .with_context(|| {
                        "semgrep: config/configFlag array entries must be non-empty strings"
                    })
            })
            .collect::<Result<Vec<_>>>()?,
        _ => anyhow::bail!("semgrep: config/configFlag must be a string or string array"),
    };

    let configs = configs
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if configs.is_empty() {
        Ok(Some(vec!["auto".to_string()]))
    } else {
        Ok(Some(configs))
    }
}

impl ScanEngine for SemgrepScanner {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        self.scan_with_cancel(target, cancellation)
    }
}
