use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use assess::assess;
pub(crate) use build_prompt_bundle::{
    build_fallback_report, build_prompt_bundle, merge_report_object, scope_has_text,
};
pub(crate) use empty_scope::{
    attach, empty_scope, merge_scope_inputs, AttachmentInput, ScopeUpdate,
};
pub(crate) use render_report_markdown::render_report_markdown;
pub(crate) use scope::{prompts, scope};

mod assess;
mod build_prompt_bundle;
mod empty_scope;
mod render_report_markdown;
mod scope;

#[cfg(test)]
mod tests;

pub(crate) fn scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

pub(crate) fn runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

pub(crate) fn load_scope(root: &Path) -> Result<Value> {
    let path = scope_path(root);
    if !path.exists() {
        return Ok(empty_scope());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read vendor assessment scope {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))
}

pub(crate) fn save_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    let path = scope_path(root);
    ensure_parent_dir(&path)?;
    write_json_pretty(&path, scope)?;
    Ok(path)
}

fn load_updated_scope(root: &Path, update: &ScopeUpdate) -> Result<Value> {
    load_scope(root)
        .map(|scope| merge_scope_inputs(scope, update))
        .and_then(|scope| save_scope(root, &scope).map(|_| scope))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    Ok(())
}

fn write_json_pretty(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(())
}

fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn json_summary(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}
