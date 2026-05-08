use super::*;

pub(crate) fn resolve_requested_path(repo_root: &Path, file_path: &Path) -> Result<PathBuf> {
    if file_path.as_os_str().is_empty() {
        bail!("source span file path is required");
    }
    if file_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!(
            "source span path {} must not contain parent traversal",
            file_path.display()
        );
    }
    Ok(if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        repo_root.join(file_path)
    })
}

pub(crate) fn display_repo_relative(repo_root: &Path, file_path: &Path) -> String {
    file_path
        .strip_prefix(repo_root)
        .unwrap_or(file_path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn looks_binaryish(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.contains(&0) {
        return true;
    }
    let control_count = bytes
        .iter()
        .filter(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0c))
        .count();
    control_count * 10 > bytes.len()
}
