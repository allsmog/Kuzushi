use crate::capabilities::vendor_assessment::domain::{
    empty_scope, merge_scope_inputs, ScopeUpdate,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

pub(super) fn runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

fn load_scope(root: &Path) -> Result<Value> {
    let path = scope_path(root);
    if !path.exists() {
        return Ok(empty_scope());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read vendor assessment scope {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))
}

pub(super) fn save_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    let path = scope_path(root);
    ensure_parent_dir(&path)?;
    write_json_pretty(&path, scope)?;
    Ok(path)
}

pub(super) fn load_updated_scope(root: &Path, update: &ScopeUpdate) -> Result<Value> {
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

pub(super) fn resolve_input_path(root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}
