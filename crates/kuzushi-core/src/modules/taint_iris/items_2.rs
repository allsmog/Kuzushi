use super::prelude::*;
use super::*;

impl TaintIrisReport {
    pub(in crate::modules) fn output(&self) -> String {
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

    pub(in crate::modules) fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
            "costUsd": self.cost_usd,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct TaintIrisPersistedRun {
    pub(in crate::modules) run_id: String,
    pub(in crate::modules) findings_db: String,
}

pub(in crate::modules) const TAINT_CWE_SELECT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint CWE selector.
Return only JSON matching:
{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"why this project should be checked"}]}.
Select only vulnerability classes that are plausible for the provided repository context."#;

pub(in crate::modules) const TAINT_IRIS_SYSTEM_PROMPT: &str = r#"You are Kuzushi's IRIS-style taint analysis agent.
Return only JSON matching:
{"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low","filePath":"relative/path","startLine":1,"message":"finding detail","sourceSinkTrace":"source -> sink proof","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}],"confidence":"high|medium|low","exploitPreconditions":"required conditions"}]}.
Only report concrete source-to-sink vulnerabilities with code evidence. Omit uncertain or hypothetical findings."#;

pub(in crate::modules) fn run_taint_cwe_select(
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
