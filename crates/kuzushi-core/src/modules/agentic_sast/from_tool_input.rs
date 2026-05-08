use super::*;

impl AgenticSastInput {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Result<Self> {
        let max_findings = agentic_sast_max_findings(input)?;
        let passes = agentic_sast_passes(input)?;
        let severity = string_list_input(input, &["severity"])?.unwrap_or_else(|| {
            vec![
                "ERROR".to_string(),
                "WARNING".to_string(),
                "INFO".to_string(),
            ]
        });
        let exclude_patterns =
            string_list_input(input, &["excludePatterns", "exclude_patterns"])?.unwrap_or_default();

        Ok(Self {
            max_findings,
            passes,
            severity,
            exclude_patterns,
        })
    }
}

fn agentic_sast_max_findings(input: &Value) -> Result<usize> {
    bounded_positive_usize_input(
        input
            .get("maxFindings")
            .or_else(|| input.get("max_findings")),
        40,
        200,
        "agentic-sast:scan maxFindings must be a positive integer",
    )
}

fn agentic_sast_passes(input: &Value) -> Result<usize> {
    let passes = bounded_positive_usize_input(
        input.get("passes"),
        1,
        2,
        "agentic-sast:scan passes must be 1 or 2",
    )?;
    anyhow::ensure!(
        matches!(passes, 1 | 2),
        "agentic-sast:scan passes must be 1 or 2"
    );
    Ok(passes)
}

fn bounded_positive_usize_input(
    value: Option<&Value>,
    default: usize,
    max: usize,
    error: &'static str,
) -> Result<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    parse_positive_usize(value, error).map(|value| value.min(max))
}

fn parse_positive_usize(value: &Value, error: &'static str) -> Result<usize> {
    let parsed = match value {
        Value::Number(number) => number.as_u64().map(|value| value as usize),
        Value::String(value) => value.parse::<usize>().ok(),
        _ => None,
    };
    parsed.filter(|value| *value > 0).context(error)
}

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
    pub(in crate::modules) fn output(&self) -> String {
        let mut lines = vec![format!(
            "agentic-sast: {} finding{} under {}",
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

    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}
