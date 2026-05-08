use super::*;

impl CarliniThreatHuntReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = vec![format!(
            "carlini-threat-hunt: {} finding{} from {} actor{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.actors,
            if self.actors == 1 { "" } else { "s" },
            self.target
        )];
        lines.push(format!("  Actor runs: {}", self.actor_runs));
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CarliniThreatHuntPersistedRun {
    pub run_id: String,
    pub findings_db: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CarliniInput {
    pub(crate) model: Option<String>,
    pub(crate) max_findings: usize,
    pub(crate) max_actors: usize,
    pub(crate) runs_per_actor: usize,
    pub(crate) prompt_context: String,
    pub(crate) debug_inline_threats: bool,
    pub(crate) prompt_override: Option<String>,
    pub(crate) attachments_block: Option<String>,
    pub(crate) kb_context: ArtifactKnowledgePromptContext,
}

impl CarliniInput {
    pub(crate) fn from_tool_input(
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        target: &Path,
    ) -> Result<Self> {
        let prompt_override = optional_string(input, &["CARLINI_THREAT_HUNT_PROMPT"])?
            .map(|value| resolve_prompt_override(&value, target))
            .transpose()?;
        let kb_context = ctx.artifact_knowledge_context(
            target,
            "carlini threat hunt actor flows threat model x-ray context",
            5,
        );
        Ok(Self {
            model: optional_string(input, &["model"])?.or_else(|| ctx.config.model.clone()),
            max_findings: read_usize(input, &["maxFindings", "max_findings"], 50, 1).min(500),
            max_actors: read_usize(input, &["maxActors", "max_actors"], 5, 1).min(100),
            runs_per_actor: read_usize(input, &["runsPerActor", "runs_per_actor"], 1, 1).min(5),
            prompt_context: optional_string(input, &["promptContext", "prompt_context"])?
                .filter(|value| {
                    matches!(value.as_str(), "actor-flows" | "actor-flows-threat-titles")
                })
                .unwrap_or_else(|| "actor-flows".to_string()),
            debug_inline_threats: bool_input(
                input,
                &["debugInlineThreats", "debug_inline_threats"],
                false,
            ),
            prompt_override,
            attachments_block: render_attachments(target)?,
            kb_context,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DfdNode {
    pub(crate) id: String,
    pub(crate) node_type: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) trust_zone: String,
}
