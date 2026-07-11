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
    let runs = crate::run_artifacts::checked_runs_root(workspace.root())?;
    collect_run_artifact_paths(workspace.root(), &runs, &mut candidates)?;
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
    let absolute = crate::workspace::validated_workspace_descendant(
        workspace.root(),
        Path::new(&source_path),
    )?;
    let metadata = match fs::symlink_metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Could not inspect artifact {}", absolute.display()))
        }
    };
    if !metadata.is_file() || !is_indexable_text_path(&absolute) {
        return Ok(None);
    }
    let metadata = json!({
        "sourceKind": if is_run_artifact_source_path(workspace.root(), &source_path) { "run-artifact" } else { "artifact-file" },
        "relativePath": source_path,
    });
    let module_id = infer_module_id(workspace, &source_path, &absolute)?;
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
}

pub(crate) fn collect_run_artifact_paths(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Artifact directory must not be a symlink: {}",
                dir.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => anyhow::bail!("Artifact path is not a directory: {}", dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", dir.display()))
        }
    }
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        collect_run_artifact_entry(root, entry?, out)?;
    }
    Ok(())
}

fn collect_run_artifact_entry(
    root: &Path,
    entry: fs::DirEntry,
    out: &mut Vec<String>,
) -> Result<()> {
    let kind = entry.file_type()?;
    if kind.is_symlink() {
        return Ok(());
    }
    let path = entry.path();
    if kind.is_dir() {
        return collect_run_artifact_paths(root, &path, out);
    }
    if kind.is_file() {
        append_indexable_run_artifact(root, &path, out);
    }
    Ok(())
}

fn append_indexable_run_artifact(root: &Path, path: &Path, out: &mut Vec<String>) {
    if is_indexable_text_path(path) {
        out.push(relative_workspace_path(root, path));
    }
}

pub(crate) fn is_indexable_text_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("json" | "jsonl" | "md" | "txt" | "svg" | "sarif")
    )
}

pub(crate) fn infer_module_id(
    workspace: &WorkspaceTarget,
    source_path: &str,
    absolute: &Path,
) -> Result<String> {
    if let Some(module_id) = infer_static_artifact_module_id(source_path) {
        return Ok(module_id);
    }
    if source_path.ends_with("run.json") {
        return infer_summary_artifact_module_id(workspace, absolute);
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

fn infer_summary_artifact_module_id(
    workspace: &WorkspaceTarget,
    absolute: &Path,
) -> Result<String> {
    let body = crate::bounded_file::read_utf8_text_within(workspace.root(), absolute, 1024 * 1024)
        .with_context(|| format!("Could not classify run artifact {}", absolute.display()))?;
    if body.contains("carliniThreatHunt") || body.contains("carlini-threat-hunt") {
        return Ok("carlini-threat-hunt".to_string());
    }
    if body.contains("xRay") || body.contains("x-ray") {
        return Ok("x-ray".to_string());
    }
    Ok("sast".to_string())
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
                relative_workspace_path(
                    root,
                    &crate::capabilities::persistent_threat_model_path(root)
                ),
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
        let source_path = relative_workspace_path(
            root,
            &crate::run_artifacts::run_dir(root, "run-1").join("report.md"),
        );

        assert_eq!(
            run_artifact_source_prefix(root),
            format!("{}/", relative_workspace_path(root, &runs_root(root)))
        );
        assert!(is_run_artifact_source_path(root, &source_path));
        assert_eq!(infer_run_id(&source_path), Some("run-1".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_discovery_rejects_symlinked_runs_root() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(target.path().join(".kuzushi/v3")).unwrap();
        fs::write(outside.path().join("report.md"), "secret").unwrap();
        symlink(outside.path(), target.path().join(".kuzushi/v3/runs")).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let error = artifact_record_candidates(&workspace).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(
            fs::read_to_string(outside.path().join("report.md")).unwrap(),
            "secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_artifact_discovery_skips_nested_symlink_directories() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run = target.path().join(".kuzushi/v3/runs/run-safe");
        fs::create_dir_all(&run).unwrap();
        fs::write(outside.path().join("report.md"), "secret").unwrap();
        symlink(outside.path(), run.join("linked")).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let candidates = artifact_record_candidates(&workspace).unwrap();

        assert!(!candidates.iter().any(|path| path.contains("linked")));
    }

    #[cfg(unix)]
    #[test]
    fn artifact_record_rejects_symlinked_persistent_artifact() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = target.path().join("outside.md");
        let linked = target.path().join("x-ray/x-ray.md");
        fs::write(&outside, "secret").unwrap();
        fs::create_dir_all(linked.parent().unwrap()).unwrap();
        symlink(&outside, &linked).unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();

        let error =
            workspace_artifact_record(&workspace, "x-ray/x-ray.md".to_string()).unwrap_err();

        assert!(error.to_string().contains("must not be a symlink"));
        assert_eq!(fs::read_to_string(outside).unwrap(), "secret");
    }
}
