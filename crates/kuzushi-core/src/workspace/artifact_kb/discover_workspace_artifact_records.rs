use super::*;

pub(crate) fn discover_workspace_artifact_records(
    workspace: &WorkspaceTarget,
) -> Result<Vec<ArtifactKnowledgeRecord>> {
    artifact_record_candidates(workspace)?
        .into_iter()
        .filter_map(|source_path| workspace_artifact_record(workspace, source_path).transpose())
        .collect()
}

fn artifact_record_candidates(workspace: &WorkspaceTarget) -> Result<Vec<String>> {
    let mut candidates = persistent_workspace_artifact_paths(workspace.root());
    candidates.extend([
        ".kuzushi/tm-artifacts/normalized-threat-model.json".to_string(),
        "x-ray/x-ray.md".to_string(),
        "x-ray/entry-points.md".to_string(),
        "x-ray/invariants.md".to_string(),
        "x-ray/architecture.svg".to_string(),
    ]);
    collect_run_artifact_paths(
        workspace.root(),
        &runs_root(workspace.root()),
        &mut candidates,
    )?;
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn persistent_workspace_artifact_paths(root: &Path) -> Vec<String> {
    [
        crate::context::context_snapshot_path(root),
        crate::capabilities::persistent_threat_model_path(root),
    ]
    .into_iter()
    .map(|path| relative_workspace_path(root, &path))
    .collect()
}

fn workspace_artifact_record(
    workspace: &WorkspaceTarget,
    source_path: String,
) -> Result<Option<ArtifactKnowledgeRecord>> {
    let absolute = workspace.root().join(&source_path);
    if !absolute.is_file() || !is_indexable_text_path(&absolute) {
        return Ok(None);
    }
    let metadata = json!({
        "sourceKind": if is_run_artifact_source_path(workspace.root(), &source_path) { "run-artifact" } else { "artifact-file" },
        "relativePath": source_path,
    });
    let module_id = infer_module_id(&source_path, &absolute)?;
    let run_id = infer_run_id(&source_path);
    let title = infer_title(&source_path, &absolute);
    ArtifactKnowledgeRecord::from_text_source(
        workspace,
        source_path,
        module_id,
        run_id,
        title,
        Vec::new(),
        metadata,
    )
    .map(Some)
    .or(Ok(None))
}

pub(crate) fn collect_run_artifact_paths(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_run_artifact_paths(root, &path, out)?;
        } else if path.is_file() && is_indexable_text_path(&path) {
            out.push(relative_workspace_path(root, &path));
        }
    }
    Ok(())
}

pub(crate) fn is_indexable_text_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("json" | "jsonl" | "md" | "txt" | "svg" | "sarif")
    )
}

pub(crate) fn infer_module_id(source_path: &str, absolute: &Path) -> Result<String> {
    if let Some(module_id) = infer_static_artifact_module_id(source_path) {
        return Ok(module_id);
    }
    if source_path.ends_with("summary.json") {
        return Ok(infer_summary_artifact_module_id(absolute));
    }
    Ok("artifact".to_string())
}

fn infer_static_artifact_module_id(source_path: &str) -> Option<String> {
    if source_path == context_snapshot_record_source_path() {
        return Some("context".to_string());
    }
    if source_path.starts_with("x-ray/") {
        return Some("x-ray".to_string());
    }
    if source_path.contains("threat-model")
        || source_path.contains("randori")
        || source_path.contains("pasta-")
    {
        return Some("threat-model".to_string());
    }
    None
}

fn infer_summary_artifact_module_id(absolute: &Path) -> String {
    let body = fs::read_to_string(absolute).unwrap_or_default();
    if body.contains("carliniThreatHunt") || body.contains("carlini-threat-hunt") {
        return "carlini-threat-hunt".to_string();
    }
    if body.contains("xRay") || body.contains("x-ray") {
        return "x-ray".to_string();
    }
    "sast".to_string()
}

fn context_snapshot_record_source_path() -> String {
    let root = Path::new("");
    relative_workspace_path(root, &crate::context::context_snapshot_path(root))
}

pub(crate) fn infer_run_id(source_path: &str) -> Option<String> {
    source_path
        .strip_prefix(&run_artifact_source_prefix(Path::new("")))
        .and_then(|suffix| suffix.split('/').next())
        .filter(|run_id| !run_id.is_empty())
        .map(ToString::to_string)
}

fn is_run_artifact_source_path(root: &Path, source_path: &str) -> bool {
    source_path.starts_with(&run_artifact_source_prefix(root))
}

fn run_artifact_source_prefix(root: &Path) -> String {
    format!("{}/", relative_workspace_path(root, &runs_root(root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_workspace_artifact_paths_use_shared_helpers() {
        let root = Path::new("/repo");

        assert_eq!(
            persistent_workspace_artifact_paths(root),
            vec![
                relative_workspace_path(root, &crate::context::context_snapshot_path(root)),
                relative_workspace_path(root, &crate::capabilities::persistent_threat_model_path(root)),
            ]
        );
    }

    #[test]
    fn context_snapshot_record_source_path_uses_context_helper() {
        assert_eq!(
            context_snapshot_record_source_path(),
            relative_workspace_path(
                Path::new(""),
                &crate::context::context_snapshot_path(Path::new(""))
            )
        );
    }

    #[test]
    fn run_artifact_source_prefix_uses_runs_root() {
        let root = Path::new("/repo");
        let source_path = relative_workspace_path(root, &crate::run_artifacts::run_dir(root, "run-1").join("report.md"));

        assert_eq!(
            run_artifact_source_prefix(root),
            format!(
                "{}/",
                relative_workspace_path(root, &runs_root(root))
            )
        );
        assert!(is_run_artifact_source_path(root, &source_path));
        assert_eq!(
            infer_run_id(&source_path),
            Some("run-1".to_string())
        );
    }
}
