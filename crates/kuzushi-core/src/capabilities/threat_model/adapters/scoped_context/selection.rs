use super::*;

pub(super) mod files;
mod inventory;

/// An authenticated context input. This never grants discovery scope or work.
pub(super) struct ContextSource {
    pub name: String,
    pub reference: Value,
    pub source: Value,
    pub paths: Vec<String>,
    pub discovery_files: Vec<String>,
    pub context_files: Vec<String>,
    pub commit: ThreatModelCommit,
    pub explicit_files: bool,
    pub inventory: Option<Value>,
}

impl ContextSource {
    pub(super) fn resolve(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Self> {
        anyhow::ensure!(
            input.get("scanScopeRef").is_none() || input.get("sourcePaths").is_none(),
            "Choose scanScopeRef or sourcePaths, never both"
        );
        if input.get("sourcePaths").is_some() {
            return files::resolve(input, ctx);
        }
        let reference: ScanScopeRef = serde_json::from_value(input["scanScopeRef"].clone())
            .context("File-group context requires an exact scanScopeRef")?;
        let scope = crate::workspace::resolve_accepted_scan_scope_selection(ctx, &reference)?;
        let commit = accepted_commit(&scope, ctx);
        let paths = scope
            .discovery_files
            .iter()
            .chain(&scope.context_files)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Self {
            name: scope.name,
            reference: json!(scope.reference),
            source: json!(scope.source),
            paths,
            discovery_files: scope.discovery_files,
            context_files: scope.context_files,
            commit,
            explicit_files: false,
            inventory: None,
        })
    }

    pub(super) fn provenance_key(&self) -> &'static str {
        if self.explicit_files {
            "fileContext"
        } else {
            "scopeContext"
        }
    }

    pub(super) fn collect(
        &self,
        build: &BuildInput,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<CodeSource> {
        let (path, policy) = if self.explicit_files {
            (
                "selected-evidence".into(),
                "selected-evidence-source-code-v1",
            )
        } else {
            let scope_id = self.reference["scopeId"]
                .as_str()
                .context("Accepted context scope identity is missing")?;
            (
                format!("accepted-group:{scope_id}"),
                "accepted-group-source-code-v1",
            )
        };
        collect_context_files(build, &self.paths, &path, policy, ctx)
    }
}

fn accepted_commit(
    scope: &AcceptedScanScopeSelection,
    ctx: &ToolExecutionContext<'_>,
) -> ThreatModelCommit {
    ThreatModelCommit {
        model_id: None,
        new_model: true,
        label: format!("{} · context draft", scope.name),
        scope: ScopeRef {
            scope_id: format!("scan-group:{}", scope.reference.scope_id),
            rel_path: PathBuf::from("."),
            project_model_sha256: scope.reference.proposal.record_hash.clone(),
            target_revision: scope
                .source
                .git_revision
                .clone()
                .unwrap_or_else(|| "unavailable".into()),
        },
        methodology: String::new(),
        source: ThreatModelRevisionSource::Build,
        source_revision_id: None,
        run_id: ctx.run_id(),
        activate: Some(false),
        actor: "tool:threat-model:build".into(),
    }
}
