use super::*;
use std::path::Component;

pub(crate) fn validated_workspace_descendant(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<PathBuf> {
    let root = canonical_workspace_root(root.as_ref())?;
    let components = normal_relative_components(relative.as_ref())?;
    let count = components.len();
    let mut path = root;
    for (index, component) in components.into_iter().enumerate() {
        path.push(component);
        reject_existing_symlink(&path)?;
        if index + 1 < count {
            reject_existing_non_directory(&path)?;
        }
    }
    Ok(path)
}

pub(crate) fn ensure_workspace_descendant_dir(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<PathBuf> {
    let mut path = canonical_workspace_root(root.as_ref())?;
    for component in normal_relative_components(relative.as_ref())? {
        path.push(component);
        ensure_real_directory(&path)?;
    }
    Ok(path)
}

pub fn ensure_workspace_output_dir(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<PathBuf> {
    ensure_workspace_descendant_dir(root, relative)
}

pub fn prepare_workspace_output_path(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<PathBuf> {
    let root = root.as_ref();
    let relative = relative.as_ref();
    if let Some(parent) = relative
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        ensure_workspace_descendant_dir(root, parent)?;
    }
    validated_workspace_descendant(root, relative)
}

pub fn write_workspace_state_file(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
    contents: &[u8],
) -> Result<PathBuf> {
    let root = root.as_ref();
    let relative = relative.as_ref();
    ensure_state_relative(relative, "writes")?;
    initialize_workspace_state(root)?;
    write_workspace_file(root, relative, contents)
}

pub fn remove_workspace_state_file(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
) -> Result<bool> {
    let root = root.as_ref();
    let relative = relative.as_ref();
    ensure_state_relative(relative, "removals")?;
    let path = validated_workspace_descendant(root, relative)?;
    remove_regular_state_file(&path)
}

pub fn write_workspace_file(
    root: impl AsRef<Path>,
    relative: impl AsRef<Path>,
    contents: &[u8],
) -> Result<PathBuf> {
    let path = prepare_workspace_output_path(root, relative)?;
    crate::fs_atomic::write_atomic_bytes(&path, contents)?;
    Ok(path)
}

pub fn read_workspace_text(root: &Path, path: &Path, max_bytes: usize) -> Result<String> {
    crate::bounded_file::read_utf8_text_within(root, path, max_bytes).map_err(|error| {
        let message = format!("Could not read workspace file {}: {error}", path.display());
        anyhow::Error::new(error).context(message)
    })
}

pub fn read_optional_workspace_text(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> Result<Option<String>> {
    if matches!(
        fs::symlink_metadata(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return Ok(None);
    }
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "Workspace file {} is outside {}",
            path.display(),
            root.display()
        )
    })?;
    let path = validated_workspace_descendant(root, relative)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() => read_workspace_text(root, &path, max_bytes).map(Some),
        Ok(_) => anyhow::bail!("Workspace path is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn ensure_state_relative(relative: &Path, operation: &str) -> Result<()> {
    if !relative.starts_with(KUZUSHI_STATE_DIR) {
        anyhow::bail!(
            "Workspace state {operation} must stay below {KUZUSHI_STATE_DIR}: {}",
            relative.display()
        );
    }
    Ok(())
}

fn remove_regular_state_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            fs::remove_file(path)
                .with_context(|| format!("Could not remove {}", path.display()))?;
            crate::fs_atomic::sync_parent_dir(path)
                .with_context(|| format!("Could not sync parent of {}", path.display()))?;
            Ok(true)
        }
        Ok(_) => anyhow::bail!("Workspace state path is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn canonical_workspace_root(root: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("Could not resolve workspace root {}", root.display()))?;
    anyhow::ensure!(
        root.is_dir(),
        "Workspace root is not a directory: {}",
        root.display()
    );
    Ok(root)
}

fn normal_relative_components(relative: &Path) -> Result<Vec<std::ffi::OsString>> {
    let components = relative.components().collect::<Vec<_>>();
    let valid = !components.is_empty()
        && components
            .iter()
            .all(|item| matches!(item, Component::Normal(_)));
    anyhow::ensure!(
        valid,
        "Workspace state path must be a non-empty relative path: {}",
        relative.display()
    );
    Ok(components
        .into_iter()
        .filter_map(|item| match item {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect())
}

fn reject_existing_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Workspace state path must not be a symlink: {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn reject_existing_non_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!(
            "Workspace state parent is not a directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "Workspace state directory must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!(
            "Workspace state path is not a directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_state_directory(path),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn create_state_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => crate::fs_atomic::sync_parent_dir(path)
            .with_context(|| format!("Could not sync parent of {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_real_directory(path)
        }
        Err(error) => Err(error).with_context(|| format!("Could not create {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn state_io_rejects_outside_symlinks() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
        fs::write(outside.path(), "outside").unwrap();
        symlink(outside.path(), workspace.path().join(".kuzushi/state.json")).unwrap();

        assert!(write_workspace_state_file(workspace.path(), ".kuzushi/state.json", b"x").is_err());
        assert!(read_optional_workspace_text(
            workspace.path(),
            &workspace.path().join(".kuzushi/state.json"),
            1024,
        )
        .is_err());
        assert!(remove_workspace_state_file(workspace.path(), ".kuzushi/state.json").is_err());
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "outside");
    }

    #[test]
    fn workspace_read_error_keeps_the_bounded_read_reason_actionable() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("oversized.json");
        fs::write(&path, "too large").unwrap();

        let error = read_workspace_text(workspace.path(), &path, 3)
            .unwrap_err()
            .to_string();

        assert!(error.contains("maximum supported size"), "{error}");
    }
}
