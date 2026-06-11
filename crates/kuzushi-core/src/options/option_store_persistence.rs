use super::{OptionBinding, OptionScope, ToolOptionStore};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

impl ToolOptionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Could not read option store {}", path.display()))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("Could not parse option store {}", path.display()))
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let body =
            serde_json::to_string_pretty(self).context("Could not serialize option store")?;
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
            .save_to_path(global_path)?;
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

fn scope_binding(binding: &OptionBinding, scope: OptionScope) -> Option<OptionBinding> {
    (binding.scope == scope).then(|| binding.clone())
}
