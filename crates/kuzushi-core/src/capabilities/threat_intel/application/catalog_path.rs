use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn resolve_catalog_path(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(explicit) = explicit_catalog_path(input, ctx)? {
        return Ok(explicit);
    }
    default_catalog_path(ctx)
}

fn explicit_catalog_path(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Option<PathBuf>> {
    let Some(raw) = input
        .get("catalogPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let resolved = resolve_explicit_catalog_path(PathBuf::from(raw), ctx)?;
    require_existing_catalog_path(&resolved)?;
    Ok(Some(resolved))
}

fn resolve_explicit_catalog_path(path: PathBuf, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(catalog_relative_base(ctx)?.join(path))
}

fn catalog_relative_base(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    ctx.workspace
        .map(|workspace| workspace.root().to_path_buf())
        .map_or_else(
            || std::env::current_dir().context("threat-intel: could not resolve current directory"),
            Ok,
        )
}

fn require_existing_catalog_path(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!(
            "threat-intel: catalogPath {} does not exist",
            path.display()
        );
    }
    Ok(())
}

fn default_catalog_path(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let dir = default_catalog_dir(ctx)?;
    ensure_catalog_dir_exists(&dir)?;
    first_toml_catalog_under(&dir)
}

fn default_catalog_dir(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let workspace = ctx.workspace.ok_or_else(missing_workspace_catalog_error)?;
    Ok(workspace.root().join(".kuzushi").join("catalogs"))
}

fn missing_workspace_catalog_error() -> anyhow::Error {
    anyhow::anyhow!(
        "threat-intel: no workspace target; pass `catalogPath` explicitly or run with --target"
    )
}

fn ensure_catalog_dir_exists(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    anyhow::bail!(
        "threat-intel: no catalog supplied. Pass `catalogPath` or create one at {}/<name>.toml",
        dir.display()
    )
}

fn first_toml_catalog_under(dir: &Path) -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("threat-intel: could not read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_toml_catalog_path(path))
        .collect();
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!(
            "threat-intel: no .toml files under {}; place a catalog there or pass `catalogPath`",
            dir.display()
        )
    })
}

fn is_toml_catalog_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
}
