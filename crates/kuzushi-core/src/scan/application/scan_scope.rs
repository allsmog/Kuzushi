use super::*;

/// A source selection resolved without following symlinks or enlarging it.
#[derive(Debug, Clone)]
pub(crate) struct ScanScope {
    pub(crate) path: PathBuf,
    pub(crate) relative: String,
    pub(crate) is_directory: bool,
}

pub(crate) fn resolve_scan_scopes(root: &Path, paths: &[String]) -> Result<Vec<ScanScope>> {
    paths
        .iter()
        .map(|path| resolve_scan_scope(root, path))
        .collect()
}

fn resolve_scan_scope(root: &Path, path: &str) -> Result<ScanScope> {
    let relative = normalized_scan_path(path)?;
    let path =
        crate::workspace::validated_workspace_descendant(root, &relative).with_context(|| {
            format!("Scan scope {relative:?} must stay inside the repository without symlinks")
        })?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("Scan scope {relative:?} does not exist under the target"))?;
    anyhow::ensure!(
        metadata.is_dir() || metadata.is_file(),
        "Scan scope {relative:?} is not a regular file or directory"
    );
    Ok(ScanScope {
        path,
        relative,
        is_directory: metadata.is_dir(),
    })
}

pub(crate) fn require_directory_scope(scope: &ScanScope, engines: &str) -> Result<()> {
    anyhow::ensure!(
        scope.is_directory,
        "{engines} requires directory scopes. File scope {:?} would scan its parent directory. Choose a directory and review the larger scope, or choose an engine that supports files. No scan started.",
        scope.relative
    );
    Ok(())
}

pub(crate) fn normalized_scan_path(path: &str) -> Result<String> {
    let mut parts = Vec::new();
    for component in Path::new(path.trim()).components() {
        match component {
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            std::path::Component::CurDir => {}
            _ => anyhow::bail!(
                "Scan scope paths must be repository-relative without parent traversal"
            ),
        }
    }
    anyhow::ensure!(!parts.is_empty(), "Scan scope paths must not be empty");
    Ok(parts.join("/"))
}
