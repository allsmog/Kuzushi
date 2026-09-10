use super::*;

impl CarliniThreatHuntReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = self.output_header_lines();
        append_carlini_persisted_run(&mut lines, self.persisted.as_ref());
        append_carlini_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            json!(self),
        );
        let observed = RuntimeCost::from_usd(self.cost_usd, "Carlini report cost")
            .expect("Carlini validates runtime cost before report construction");
        let cost = if self.cost_usd_exact {
            RuntimeCostReport::known(observed)
        } else {
            RuntimeCostReport::incomplete(observed)
        };
        crate::module_result::apply_runtime_cost_report(&mut output, cost);
        output
    }

    fn summary(&self) -> String {
        format!(
            "carlini-threat-hunt: {} finding{}, {} rejected by finding schema under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.rejected_count,
            self.target
        )
    }

    fn output_header_lines(&self) -> Vec<String> {
        vec![
            format!(
                "carlini-threat-hunt: {} finding{} from {} actor{} under {}",
                self.count,
                plural_suffix(self.count),
                self.actors,
                plural_suffix(self.actors),
                self.target
            ),
            format!("  Actor runs: {}", self.actor_runs),
            format!("  Rejected by finding schema: {}", self.rejected_count),
            format!(
                "  Prompt source files: {} ({} threat-focused)",
                self.prompt_inventory_files, self.threat_focused_prompt_files
            ),
        ]
    }
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn append_carlini_persisted_run(
    lines: &mut Vec<String>,
    persisted: Option<&CarliniThreatHuntPersistedRun>,
) {
    let Some(persisted) = persisted else {
        return;
    };
    lines.push(format!(
        "  Persisted run: {} ({})",
        persisted.run_id, persisted.findings_db
    ));
}

fn append_carlini_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(findings.iter().take(10).map(carlini_finding_line));
    append_carlini_remaining_count(lines, findings.len());
}

fn carlini_finding_line(finding: &Finding) -> String {
    format!(
        "  - {} - {} - {}:{}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.file_path,
        finding.start_line
    )
}

fn append_carlini_remaining_count(lines: &mut Vec<String>, finding_count: usize) {
    if finding_count > 10 {
        lines.push(format!("  ... and {} more", finding_count - 10));
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
        let kb_context = carlini_context_for_input(ctx, target, input)?;
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

fn carlini_context_for_input(
    ctx: &ToolExecutionContext<'_>, target: &Path, input: &Value,
) -> Result<ArtifactKnowledgePromptContext> {
    use crate::capabilities::threat_model::{load_selected_threat_model, ThreatModelSelection};
    let selection = ThreatModelSelection::from_input(input)?;
    let mut context = carlini_artifact_context(ctx, target);
    if !selection.is_bound() { return Ok(context); }
    let document = load_selected_threat_model(target, &selection)?;
    let previous_count = context.snippets.len();
    context.snippets.retain(|snippet| !is_mutable_model_context(snippet));
    let omitted = previous_count - context.snippets.len();
    if let Some(document) = document {
        context.snippets.insert(0, selected_model_snippet(&selection, &document)?);
    }
    context.status = format!("selected immutable threat-model context; {omitted} mutable model/lead snippet(s) replaced or omitted; other artifact context retains its recorded sources");
    Ok(context)
}

fn is_mutable_model_context(snippet: &ArtifactKnowledgeSnippet) -> bool {
    matches!(snippet.module_id.as_str(), "threat-model" | "threat-leads")
        || snippet.source_path.contains("threat-model")
        || snippet.source_path.contains("threat-leads")
}

fn selected_model_snippet(
    selection: &crate::capabilities::threat_model::ThreatModelSelection, document: &Value,
) -> Result<ArtifactKnowledgeSnippet> {
    let crate::capabilities::threat_model::ThreatModelSelection::Revision(reference) = selection else {
        anyhow::bail!("selected model document requires a revision reference");
    };
    let body = serde_json::to_string(document)?;
    Ok(ArtifactKnowledgeSnippet {
        source_path: format!("threat-model:{}@{} ({})", reference.model_id, reference.revision_id, reference.sha256),
        module_id: "threat-model".to_string(), run_id: None,
        title: "Selected threat-model revision".to_string(),
        summary: "The immutable revision explicitly supplied to this run.".to_string(),
        snippet: compact_carlini_context_text(&body, 1200), refs: Vec::new(),
    })
}

pub(crate) fn carlini_artifact_context(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> ArtifactKnowledgePromptContext {
    let refresh = refresh_carlini_workspace_artifacts(ctx, target);
    let context = ctx.artifact_knowledge_context(
        target,
        "carlini threat hunt actor flows threat model x-ray context",
        20,
    );
    let mut context = select_carlini_artifact_context(context, target);
    append_carlini_refresh_status(&mut context, refresh);
    context
}

fn select_carlini_artifact_context(
    context: ArtifactKnowledgePromptContext,
    target: &Path,
) -> ArtifactKnowledgePromptContext {
    if context.snippets.is_empty() {
        return context_with_explicit_carlini_snippets(context, target);
    }
    let mut context = context;
    let preferred = preferred_carlini_context_snippets(target, &context.snippets);
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

fn refresh_carlini_workspace_artifacts(
    ctx: &ToolExecutionContext<'_>,
    target: &Path,
) -> Result<crate::artifact_kb::ArtifactRefreshReport> {
    let workspace = ctx
        .workspace
        .filter(|workspace| workspace.root() == target)
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| crate::workspace::WorkspaceTarget::new(target))?;
    crate::artifact_kb::refresh_workspace_artifacts(&workspace)
}

fn append_carlini_refresh_status(
    context: &mut ArtifactKnowledgePromptContext,
    refresh: Result<crate::artifact_kb::ArtifactRefreshReport>,
) {
    match refresh {
        Ok(report) if report.partial => context.status.push_str(&format!(
            "; bounded refresh partial (indexed {}, unchanged {})",
            report.indexed, report.unchanged
        )),
        Ok(_) => {}
        Err(error) => {
            context
                .status
                .push_str(&format!("; bounded refresh unavailable: {error}"));
        }
    }
}

fn context_with_explicit_carlini_snippets(
    mut context: ArtifactKnowledgePromptContext,
    target: &Path,
) -> ArtifactKnowledgePromptContext {
    context.snippets = explicit_carlini_context_snippets(target);
    if !context.snippets.is_empty() {
        context.status = format!(
            "available, {} explicit threat-leads/threat-model/x-ray/context snippet(s)",
            context.snippets.len()
        );
    }
    context
}

fn preferred_carlini_context_snippets(
    target: &Path,
    snippets: &[ArtifactKnowledgeSnippet],
) -> Vec<ArtifactKnowledgeSnippet> {
    let mut preferred = explicit_carlini_context_snippets(target);
    preferred.extend(
        snippets
            .iter()
            .filter(|snippet| is_carlini_context_artifact(snippet))
            .cloned(),
    );
    unique_carlini_context_snippets(preferred)
        .into_iter()
        .take(6)
        .collect()
}

fn is_carlini_context_artifact(snippet: &ArtifactKnowledgeSnippet) -> bool {
    matches!(
        snippet.module_id.as_str(),
        "x-ray" | "threat-model" | "threat-leads" | "context"
    ) || snippet.source_path.starts_with("x-ray/")
        || snippet.source_path.contains("threat-leads")
        || snippet.source_path.contains("threat-model")
        || is_context_snapshot_source_path(&snippet.source_path)
}

fn explicit_carlini_context_snippets(target: &Path) -> Vec<ArtifactKnowledgeSnippet> {
    let mut sources = vec![
        (
            ".kuzushi/threat-leads.md".to_string(),
            "threat-leads",
            "threat-leads.md",
        ),
        (
            ".kuzushi/threat-leads.json".to_string(),
            "threat-leads",
            "threat-leads.json",
        ),
        (
            "x-ray/entry-points.md".to_string(),
            "x-ray",
            "entry-points.md",
        ),
        ("x-ray/x-ray.md".to_string(), "x-ray", "x-ray.md"),
        ("x-ray/invariants.md".to_string(), "x-ray", "invariants.md"),
    ];
    sources.extend([
        (
            persistent_threat_model_source_path(target),
            "threat-model",
            "threat-model.json",
        ),
        (
            context_snapshot_source_path(target),
            "context",
            "context-snapshot.json",
        ),
    ]);
    sources
        .into_iter()
        .filter_map(|(source_path, module_id, title)| {
            explicit_context_snippet(target, &source_path, module_id, title)
        })
        .collect()
}

fn persistent_threat_model_source_path(target: &Path) -> String {
    crate::workspace::artifact_kb::relative_workspace_path(
        target,
        &crate::capabilities::persistent_threat_model_path(target),
    )
}

fn context_snapshot_source_path(target: &Path) -> String {
    crate::workspace::artifact_kb::relative_workspace_path(
        target,
        &crate::context::context_snapshot_path(target),
    )
}

fn is_context_snapshot_source_path(source_path: &str) -> bool {
    let relative = context_snapshot_source_path(Path::new(""));
    source_path == relative || source_path.ends_with(&format!("/{relative}"))
}

fn explicit_context_snippet(
    target: &Path,
    source_path: &str,
    module_id: &str,
    title: &str,
) -> Option<ArtifactKnowledgeSnippet> {
    let body = load_context_snippet_body(target, source_path)?;
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

fn load_context_snippet_body(target: &Path, source_path: &str) -> Option<String> {
    if source_path == persistent_threat_model_source_path(target) {
        let document = crate::capabilities::try_load_persistent_threat_model(target)
            .ok()
            .flatten()?;
        return serde_json::to_string(&document).ok();
    }
    let path = target.join(source_path);
    crate::bounded_file::read_utf8_text_within(target, &path, 2 * 1024 * 1024).ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_context_replaces_active_model_and_unbound_lead_snippets() {
        let root = tempfile::tempdir().unwrap();
        let first = crate::capabilities::threat_model::commit_test_model(root.path(), "ACCEPTED_ALPHA");
        crate::capabilities::threat_model::commit_test_model(root.path(), "ACTIVE_BETA");
        fs::write(root.path().join(".kuzushi/threat-leads.md"), "ACTIVE_BETA_LEAD").unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::config::V2Config::default();
        let ctx = ToolExecutionContext { config: &config, workspace: Some(&workspace), findings_store: None,
            trace: None, cancellation: None, authorization: Default::default() };
        let input = json!({"threatModelRef": first});
        let document = resolve_threat_model_document(&input, root.path()).unwrap();
        assert_eq!(document["title"], "ACCEPTED_ALPHA");
        let options = CarliniInput::from_tool_input(&input, &ctx, root.path()).unwrap();
        let context = serde_json::to_string(&options.kb_context).unwrap();
        assert!(context.contains("ACCEPTED_ALPHA"), "{context}");
        assert!(!context.contains("ACTIVE_BETA"), "{context}");
        assert!(context.contains("replaced or omitted"));
    }

    #[test]
    fn explicit_carlini_context_snippets_use_shared_persistent_artifact_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(crate::workspace::workspace_state_root(temp.path())).unwrap();
        fs::write(
            crate::capabilities::persistent_threat_model_path(temp.path()),
            "{}\n",
        )
        .unwrap();
        fs::write(crate::context::context_snapshot_path(temp.path()), "{}\n").unwrap();

        let snippets = explicit_carlini_context_snippets(temp.path());
        let source_paths = snippets
            .iter()
            .map(|snippet| snippet.source_path.as_str())
            .collect::<Vec<_>>();

        assert!(source_paths.contains(&persistent_threat_model_source_path(temp.path()).as_str()));
        assert!(source_paths.contains(&context_snapshot_source_path(temp.path()).as_str()));
        assert!(snippets
            .iter()
            .any(|snippet| snippet.module_id == "context" && is_carlini_context_artifact(snippet)));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_context_skips_symlinks_outside_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside-threat-leads.md");
        fs::create_dir_all(target.join(".kuzushi")).unwrap();
        fs::write(&outside, "OUTSIDE_CARLINI_CONTEXT_TOKEN\n").unwrap();
        symlink(&outside, target.join(".kuzushi/threat-leads.md")).unwrap();

        let snippets = explicit_carlini_context_snippets(&target);
        let text = snippets
            .iter()
            .map(|snippet| format!("{}\n{}", snippet.summary, snippet.snippet))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!text.contains("OUTSIDE_CARLINI_CONTEXT_TOKEN"));
        assert!(snippets
            .iter()
            .all(|snippet| snippet.source_path != ".kuzushi/threat-leads.md"));
    }
}
