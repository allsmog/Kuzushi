use crate::capabilities::plugin_adapters::domain::PluginAdapterSpec;
use crate::modules::ToolExecutionContext;
use crate::runtime::resolve_explicit_model;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) fn resolve_required_plugin_root(
    input: &Value,
    spec: PluginAdapterSpec<'_>,
) -> Result<PathBuf> {
    let raw = string_input_any(input, &["pluginRoot", "pluginPath", "plugin_root", "plugin_path"])
        .or_else(|| {
            std::env::var(spec.env_var)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
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

pub(crate) fn resolve_tool_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        return resolve_explicit_target(target, ctx);
    }

    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }

    anyhow::bail!("plugin adapter requires an explicit active workspace")
}

fn resolve_explicit_target(target: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("plugin adapter target may not be blank")
    }
    resolve_absolute_or_relative_path(PathBuf::from(trimmed), ctx)
}

fn resolve_absolute_or_relative_path(
    candidate: PathBuf,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        let workspace = ctx
            .workspace
            .context("plugin adapter requires an explicit active workspace")?;
        Ok(workspace.root().join(candidate))
    }
}

pub(crate) fn resolve_tool_model(
    tool_name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    resolve_explicit_model(
        tool_name,
        string_input_any(input, &["model"]),
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn string_input_any(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(crate) fn string_array_or_csv_input(input: &Value, keys: &[&str]) -> Option<Vec<String>> {
    keys.iter().find_map(|key| match input.get(*key) {
        Some(Value::String(value)) => Some(split_csv(value)),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect(),
        ),
        _ => None,
    })
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn positive_usize_input(
    input: &Value,
    keys: &[&str],
    label: &str,
) -> Result<Option<usize>> {
    let Some(value) = keys.iter().find_map(|key| input.get(*key)) else {
        return Ok(None);
    };
    match value {
        Value::Number(number) => {
            let value = number
                .as_u64()
                .with_context(|| format!("{label} must be a positive integer"))?;
            positive_usize(value, label)
        }
        Value::String(value) => {
            let parsed = value
                .trim()
                .parse::<u64>()
                .with_context(|| format!("{label} must be a positive integer"))?;
            positive_usize(parsed, label)
        }
        _ => anyhow::bail!("{label} must be a positive integer"),
    }
}

fn positive_usize(value: u64, label: &str) -> Result<Option<usize>> {
    if value == 0 {
        anyhow::bail!("{label} must be a positive integer");
    }
    Ok(Some(value as usize))
}
