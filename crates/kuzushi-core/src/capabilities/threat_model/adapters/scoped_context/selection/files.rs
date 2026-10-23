use super::*;
use std::path::Component;

pub(super) fn resolve(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<ContextSource> {
    let root = ctx
        .workspace
        .context("Evidence context requires a repository")?
        .root();
    let reference: ThreatModelRef = serde_json::from_value(input["inheritedContextRef"].clone())
        .context("sourcePaths requires an exact non-null inheritedContextRef")?;
    let document = load_exact_threat_model(root, &reference)?;
    let mut commit = exact_verification::checked_revision_request(root, &reference, ctx.run_id())?;
    let paths = checked_paths(&input["sourcePaths"])?;
    require_parent_membership(&paths, &document, &commit.scope, ctx)?;
    let inventory = require_inventory_membership(&paths, ctx)?;
    let current = inventory
        .pointer("/source/treeHash")
        .and_then(Value::as_str)
        .context("Evidence inventory has no authenticated source identity")?
        .to_owned();
    exact_verification::require_recorded_source(&document, &commit.scope, root, &current)?;
    commit.model_id = None;
    commit.new_model = true;
    commit.label = format!("{} · evidence context draft", commit.label);
    commit.source = ThreatModelRevisionSource::Build;
    commit.actor = "tool:threat-model:build".into();
    Ok(ContextSource {
        name: "Selected evidence files".into(),
        reference: Value::Null,
        source: json!({"treeHash":current,"git":crate::workspace::target_git_metadata(root)}),
        discovery_files: Vec::new(),
        context_files: paths.clone(),
        paths,
        commit,
        explicit_files: true,
        inventory: Some(inventory),
    })
}

pub(crate) fn checked_paths(value: &Value) -> Result<Vec<String>> {
    let paths: Vec<String> =
        serde_json::from_value(value.clone()).context("sourcePaths must be literal file paths")?;
    anyhow::ensure!(
        !paths.is_empty() && paths.len() <= 256,
        "Choose 1 to 256 exact evidence files"
    );
    let mut seen = BTreeSet::new();
    for path in &paths {
        require_literal_file(path)?;
        anyhow::ensure!(seen.insert(path), "Repeated evidence file: {path:?}");
    }
    Ok(paths)
}

fn require_literal_file(path: &str) -> Result<()> {
    anyhow::ensure!(
        !path.is_empty() && !path.contains('\0') && !path.contains("://"),
        "Invalid evidence file: {path:?}"
    );
    anyhow::ensure!(
        Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "Evidence must be repository-relative without traversal: {path:?}"
    );
    let canonical = Path::new(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    anyhow::ensure!(
        canonical == path,
        "Evidence file spelling is not canonical: {path:?}"
    );
    Ok(())
}

fn require_parent_membership(
    paths: &[String],
    document: &Value,
    scope: &ScopeRef,
    ctx: &ToolExecutionContext<'_>,
) -> Result<()> {
    if let Some(value) = document.pointer("/provenance/fileContext/receipt/sourcePaths") {
        return require_subset(paths, &checked_paths(value)?);
    }
    if let Some(value) = document.pointer("/provenance/scopeContext/receipt/scopeRef") {
        let reference =
            serde_json::from_value(value.clone()).context("Parent group reference is malformed")?;
        let parent = crate::workspace::resolve_accepted_scan_scope_selection(ctx, &reference)?;
        return require_subset(
            paths,
            &parent
                .discovery_files
                .into_iter()
                .chain(parent.context_files)
                .collect::<Vec<_>>(),
        );
    }
    if scope.rel_path != Path::new(".") {
        anyhow::ensure!(
            paths
                .iter()
                .all(|path| Path::new(path).starts_with(&scope.rel_path)),
            "Evidence leaves the inherited context scope"
        );
    }
    Ok(())
}

fn require_subset(paths: &[String], allowed: &[String]) -> Result<()> {
    let allowed = allowed.iter().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        paths.iter().all(|path| allowed.contains(path)),
        "Evidence leaves the inherited context file group"
    );
    Ok(())
}

pub(in crate::capabilities::threat_model::adapters::scoped_context) fn require_inventory_membership(
    paths: &[String],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    super::inventory::resolve(paths, ctx)
}
