use super::prelude::*;
use super::*;

impl AgenticSastInput {
    pub(in crate::modules) fn from_tool_input(input: &Value) -> Result<Self> {
        let max_findings = match input
            .get("maxFindings")
            .or_else(|| input.get("max_findings"))
        {
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| *value > 0)
                .context("agentic-sast:scan maxFindings must be a positive integer")?
                .min(200) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .ok()
                .filter(|value| *value > 0)
                .context("agentic-sast:scan maxFindings must be a positive integer")?
                .min(200),
            Some(_) => anyhow::bail!("agentic-sast:scan maxFindings must be a positive integer"),
            None => 40,
        };
        let passes = match input.get("passes") {
            Some(Value::Number(number)) => number
                .as_u64()
                .filter(|value| matches!(*value, 1 | 2))
                .context("agentic-sast:scan passes must be 1 or 2")?
                as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .ok()
                .filter(|value| matches!(*value, 1 | 2))
                .context("agentic-sast:scan passes must be 1 or 2")?,
            Some(_) => anyhow::bail!("agentic-sast:scan passes must be 1 or 2"),
            None => 1,
        };
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
