use super::{OptionBinding, OptionScope, ToolOptionStore};
use anyhow::{Context, Result};
use std::path::Path;

const MAX_OPTION_STORE_BYTES: usize = 16 * 1024 * 1024;

impl ToolOptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = match standard_option_store_root(path).filter(|root| root.is_dir()) {
            Some(root) => {
                crate::workspace::read_optional_workspace_text(root, path, MAX_OPTION_STORE_BYTES)?
            }
            None => match crate::bounded_file::read_utf8_text(path, MAX_OPTION_STORE_BYTES) {
                Ok(raw) => Some(raw),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("Could not read option store {}", path.display()))
                }
            },
        };
        let Some(raw) = raw else {
            return Ok(Self::new());
        };
        serde_json::from_str(&raw)
            .with_context(|| format!("Could not parse option store {}", path.display()))
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        self.save_scoped_path(path, OptionScope::Workspace)
    }

    fn save_scoped_path(&self, path: &Path, scope: OptionScope) -> Result<()> {
        let body =
            serde_json::to_string_pretty(self).context("Could not serialize option store")?;
        if let Some(root) = standard_option_store_root(path).filter(|root| root.is_dir()) {
            let relative = path
                .strip_prefix(root)
                .context("Option store path escaped its storage root")?;
            if scope == OptionScope::Global {
                // Operator state keeps containment and no-follow checks without
                // applying repository tracking rules to the operator's home.
                crate::workspace::write_workspace_file(root, relative, body.as_bytes())?;
            } else {
                crate::workspace::write_workspace_state_file(root, relative, body.as_bytes())?;
            }
            return Ok(());
        }
        crate::fs_atomic::write_atomic(path, &body)
            .with_context(|| format!("Could not write option store {}", path.display()))
    }

    pub fn load_persistent(global_path: &Path, workspace_path: Option<&Path>) -> Result<Self> {
        let mut store = Self::new();
        store.merge_scope(Self::load_from_path(global_path)?, OptionScope::Global);
        if let Some(path) = workspace_path {
            store.merge_scope(Self::load_from_path(path)?, OptionScope::Workspace);
        }
        Ok(store)
    }

    pub fn save_persistent(&self, global_path: &Path, workspace_path: Option<&Path>) -> Result<()> {
        self.scope_only(OptionScope::Global)
            .save_scoped_path(global_path, OptionScope::Global)?;
        if let Some(path) = workspace_path {
            self.scope_only(OptionScope::Workspace).save_to_path(path)?;
        }
        Ok(())
    }

    pub fn merge_store(&mut self, other: Self) {
        for (binding, values) in other.bindings {
            self.bindings.entry(binding).or_default().extend(values);
        }
    }

    pub fn merge_scope(&mut self, other: Self, scope: OptionScope) {
        self.merge_store(other.scope_only(scope));
    }

    pub fn scope_only(&self, scope: OptionScope) -> Self {
        let bindings = self
            .bindings
            .iter()
            .filter_map(|(binding, values)| {
                scope_binding(binding, scope).map(|binding| (binding, values.clone()))
            })
            .collect();
        Self { bindings }
    }
}

fn standard_option_store_root(path: &Path) -> Option<&Path> {
    (path.file_name()?.to_str()? == crate::workspace::WORKSPACE_OPTIONS_FILE).then_some(())?;
    let version = path.parent()?;
    (version.file_name()?.to_str()? == crate::workspace::WORKSPACE_STATE_VERSION_DIR)
        .then_some(())?;
    let state = version.parent()?;
    (state.file_name()?.to_str()? == crate::workspace::KUZUSHI_STATE_DIR).then_some(())?;
    state.parent()
}

fn scope_binding(binding: &OptionBinding, scope: OptionScope) -> Option<OptionBinding> {
    (binding.scope == scope).then(|| binding.clone())
}

#[cfg(test)]
mod tests;
