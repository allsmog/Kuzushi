use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::Value;

use super::string_input_any;

#[derive(Debug, Clone, Copy)]
pub(super) struct PluginAdapterSpec<'a> {
    pub(super) tool_name: &'a str,
    pub(super) tool_slug: &'static str,
    pub(super) package_name: &'static str,
    pub(super) env_var: &'static str,
    pub(super) install_hint: &'static str,
    pub(super) prompt_title: &'static str,
    pub(super) allow_skill_filter: bool,
}

pub(super) fn resolve_required_plugin_root(
    input: &Value,
    spec: PluginAdapterSpec<'_>,
) -> Result<PathBuf> {
    let raw = string_input_any(input, &["pluginRoot", "pluginPath", "plugin_root", "plugin_path"])
        .or_else(|| std::env::var(spec.env_var).ok().filter(|value| !value.trim().is_empty()))
        .with_context(|| {
            format!(
                "{} requires {}. Install with `{}` or pass {{\"pluginRoot\":\"/path/to/plugin\"}} or set {}.",
                spec.tool_name, spec.package_name, spec.install_hint, spec.env_var
            )
        })?;
    let path = PathBuf::from(raw.trim());
    if !path.exists() {
        anyhow::bail!(
            "{} plugin root does not exist: {}. Install with `{}` or update {}.",
            spec.tool_name,
            path.display(),
            spec.install_hint,
            spec.env_var
        );
    }
    Ok(path)
}
