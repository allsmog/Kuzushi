use super::*;

impl TaintIrisReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = vec![format!(
            "taint-iris: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )];
        if self.cwes.is_empty() {
            lines.push("  CWE classes: none selected".to_string());
        } else {
            lines.push(format!(
                "  CWE classes: {}",
                self.cwes
                    .iter()
                    .map(|cwe| cwe.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
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

    pub(crate) fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }
}

pub(crate) fn run_taint_cwe_select(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let model = optional_nonempty_string(&input, "model")?.or_else(|| ctx.config.model.clone());
    let cwes = run_taint_cwe_select_value(&input, &target, runtime, model.as_deref())?;
    Ok(json!({
        "ok": true,
        "output": format!("pipeline:taint-cwe-select selected {} CWE class{}", cwes.len(), if cwes.len() == 1 { "" } else { "es" }),
        "data": {
            "target": target.display().to_string(),
            "cwes": cwes,
        },
    }))
}
