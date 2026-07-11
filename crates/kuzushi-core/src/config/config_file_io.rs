use super::*;

const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

pub(super) fn read_optional_config(path: &Path) -> Result<Option<String>> {
    if let Some(root) = standard_config_root(path) {
        match std::fs::symlink_metadata(root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Could not inspect config root {}", root.display()))
            }
            Ok(_) => {}
        }
        return crate::workspace::read_optional_workspace_text(root, path, MAX_CONFIG_BYTES);
    }
    match crate::bounded_file::read_utf8_text(path, MAX_CONFIG_BYTES) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
    }
}

pub(super) fn write_config_body(path: &Path, body: String) -> Result<()> {
    if let Some(root) = standard_config_root(path) {
        let relative = path
            .strip_prefix(root)
            .context("Config path escaped its workspace root")?;
        crate::workspace::write_workspace_state_file(root, relative, body.as_bytes())?;
        return Ok(());
    }
    crate::fs_atomic::write_atomic(path, &body)
        .with_context(|| format!("Could not write {}", path.display()))
}

fn standard_config_root(path: &Path) -> Option<&Path> {
    (path.file_name()?.to_str()? == crate::workspace::WORKSPACE_CONFIG_FILE).then_some(())?;
    let version = path.parent()?;
    (version.file_name()?.to_str()? == crate::workspace::WORKSPACE_STATE_VERSION_DIR)
        .then_some(())?;
    let state = version.parent()?;
    (state.file_name()?.to_str()? == crate::workspace::KUZUSHI_STATE_DIR).then_some(())?;
    state.parent()
}
