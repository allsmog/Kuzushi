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
        lines.push(format!(
            "  Prompt source files: {} ({} threat-focused)",
            self.prompt_inventory_files, self.threat_focused_prompt_files
        ));
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

impl CarliniInput {
    pub(crate) fn from_tool_input(
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        target: &Path,
    ) -> Result<Self> {
        let prompt_override = optional_string(input, &["CARLINI_THREAT_HUNT_PROMPT"])?
            .map(|value| resolve_prompt_override(&value, target))
            .transpose()?;
        let kb_context = carlini_artifact_context(ctx, target);
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

pub(crate) fn carlini_artifact_context(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> ArtifactKnowledgePromptContext {
    let workspace = ctx
        .workspace
        .filter(|workspace| workspace.root() == target)
        .cloned()
        .or_else(|| crate::workspace::WorkspaceTarget::new(target).ok());
    if let Some(workspace) = &workspace {
        let _ = crate::artifact_kb::index_workspace_artifacts(workspace);
    }

    let mut context = ctx.artifact_knowledge_context(
        target,
        "carlini threat hunt actor flows threat model x-ray context",
        20,
    );
    if context.snippets.is_empty() {
        context.snippets = explicit_carlini_context_snippets(target);
        if !context.snippets.is_empty() {
            context.status = format!(
                "available, {} explicit threat-leads/threat-model/x-ray/context snippet(s)",
                context.snippets.len()
            );
        }
        return context;
    }

    let mut preferred = explicit_carlini_context_snippets(target);
    preferred.extend(
        context
            .snippets
            .iter()
            .filter(|snippet| is_carlini_context_artifact(snippet))
            .cloned(),
    );
    preferred = unique_carlini_context_snippets(preferred);
    let preferred = preferred.into_iter().take(6).collect::<Vec<_>>();
    if preferred.is_empty() {
        context.snippets.truncate(6);
        return context;
    }

    context.snippets = preferred;
    context.status = format!(
        "available, {} preferred threat-leads/threat-model/x-ray/context snippet(s)",
        context.snippets.len()
    );
    context
}

fn is_carlini_context_artifact(snippet: &ArtifactKnowledgeSnippet) -> bool {
    matches!(
        snippet.module_id.as_str(),
        "x-ray" | "threat-model" | "threat-leads" | "context"
    ) || snippet.source_path.starts_with("x-ray/")
        || snippet.source_path.contains("threat-leads")
        || snippet.source_path.contains("threat-model")
        || snippet
            .source_path
            .ends_with(".kuzushi/context-snapshot.json")
}

fn explicit_carlini_context_snippets(target: &Path) -> Vec<ArtifactKnowledgeSnippet> {
    [
        (
            ".kuzushi/threat-leads.md",
            "threat-leads",
            "threat-leads.md",
        ),
        (
            ".kuzushi/threat-leads.json",
            "threat-leads",
            "threat-leads.json",
        ),
        ("x-ray/entry-points.md", "x-ray", "entry-points.md"),
        ("x-ray/x-ray.md", "x-ray", "x-ray.md"),
        ("x-ray/invariants.md", "x-ray", "invariants.md"),
        (
            ".kuzushi/threat-model.json",
            "threat-model",
            "threat-model.json",
        ),
        (
            ".kuzushi/context-snapshot.json",
            "context",
            "context-snapshot.json",
        ),
    ]
    .into_iter()
    .filter_map(|(source_path, module_id, title)| {
        explicit_context_snippet(target, source_path, module_id, title)
    })
    .collect()
}

fn explicit_context_snippet(
    target: &Path,
    source_path: &str,
    module_id: &str,
    title: &str,
) -> Option<ArtifactKnowledgeSnippet> {
    let body = fs::read_to_string(target.join(source_path)).ok()?;
    let snippet_limit = if source_path.ends_with("threat-leads.md") {
        5000
    } else {
        1200
    };
    let snippet = compact_carlini_context_text(&body, snippet_limit);
    Some(ArtifactKnowledgeSnippet {
        source_path: source_path.to_string(),
        module_id: module_id.to_string(),
        run_id: None,
        title: title.to_string(),
        summary: body
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or(title)
            .chars()
            .take(240)
            .collect(),
        snippet,
        refs: Vec::new(),
    })
}

fn unique_carlini_context_snippets(
    snippets: Vec<ArtifactKnowledgeSnippet>,
) -> Vec<ArtifactKnowledgeSnippet> {
    let mut seen = BTreeSet::new();
    snippets
        .into_iter()
        .filter(|snippet| seen.insert(snippet.source_path.clone()))
        .collect()
}

fn compact_carlini_context_text(text: &str, max_chars: usize) -> String {
    let mut compact = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if compact.chars().count() > max_chars {
        compact = compact.chars().take(max_chars).collect::<String>();
        compact.push_str("...");
    }
    compact
}
