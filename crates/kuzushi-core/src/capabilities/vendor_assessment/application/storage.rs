use crate::capabilities::vendor_assessment::domain::{
    empty_scope, merge_scope_inputs, ScopeUpdate,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

const MAX_VENDOR_SCOPE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

pub(super) fn runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

pub(super) fn load_scope(root: &Path) -> Result<Value> {
    let path = scope_path(root);
    let raw = match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(empty_scope()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Could not inspect vendor assessment scope {}",
                    path.display()
                )
            });
        }
        Ok(_) => crate::bounded_file::read_utf8_text_within(root, &path, MAX_VENDOR_SCOPE_BYTES)
            .with_context(|| {
                format!("Could not read vendor assessment scope {}", path.display())
            })?,
    };
    let scope = serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))?;
    validate_scope(&scope)?;
    Ok(scope)
}

pub(super) fn save_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    validate_scope(scope)?;
    let path = scope_path(root);
    write_json_pretty(root, &path, scope)
}

pub(super) fn load_updated_scope(root: &Path, update: &ScopeUpdate) -> Result<Value> {
    let scope = proposed_scope(root, update)?;
    if !update.is_empty() {
        save_scope(root, &scope)?;
    }
    Ok(scope)
}

pub(super) fn proposed_scope(root: &Path, update: &ScopeUpdate) -> Result<Value> {
    merge_scope_inputs(load_scope(root)?, update)
}

fn validate_scope(scope: &Value) -> Result<()> {
    anyhow::ensure!(
        scope.is_object(),
        "vendor scope must be a JSON object; existing state was preserved"
    );
    for key in [
        "vendorName",
        "productName",
        "primaryDomain",
        "useCase",
        "profile",
    ] {
        anyhow::ensure!(
            scope.get(key).is_none_or(Value::is_string),
            "vendor scope field {key} must be text; existing state was preserved"
        );
    }
    for key in ["dataClasses", "integrations"] {
        validate_string_list(scope.get(key), key)?;
    }
    validate_documents(scope.get("documents"))
}

fn validate_string_list(value: Option<&Value>, key: &str) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let array = value
        .as_array()
        .with_context(|| format!("vendor scope field {key} must be an array"))?;
    anyhow::ensure!(
        array.iter().all(Value::is_string),
        "vendor scope field {key} must contain text"
    );
    Ok(())
}

fn validate_documents(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let docs = value
        .as_array()
        .context("vendor scope documents must be an array; existing state was preserved")?;
    for doc in docs {
        anyhow::ensure!(
            doc.is_object(),
            "vendor scope documents must contain objects"
        );
        anyhow::ensure!(
            doc.get("text").is_none_or(Value::is_string),
            "vendor document text must be a string"
        );
    }
    Ok(())
}

fn write_json_pretty(root: &Path, path: &Path, value: &Value) -> Result<PathBuf> {
    let body = format!("{}\n", serde_json::to_string_pretty(value)?);
    anyhow::ensure!(body.len() <= MAX_VENDOR_SCOPE_BYTES, "vendor scope exceeds the 8 MiB storage limit; reduce attached evidence. Existing state was preserved.");
    write_state_path(root, path, body.as_bytes())
}

pub(super) fn write_state_path(root: &Path, path: &Path, body: &[u8]) -> Result<PathBuf> {
    let relative = state_relative_path(root, path)?;
    crate::workspace::write_workspace_state_file(root, relative, body)
        .with_context(|| format!("Could not write {}", path.display()))
}

pub(super) fn prepare_state_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let relative = state_relative_path(root, path)?;
    crate::workspace::prepare_workspace_output_path(root, relative)
}

fn state_relative_path<'a>(root: &Path, path: &'a Path) -> Result<&'a Path> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "Vendor assessment artifact {} is outside workspace {}",
            path.display(),
            root.display()
        )
    })?;
    anyhow::ensure!(
        relative.starts_with(crate::workspace::KUZUSHI_STATE_DIR),
        "Vendor assessment artifact must stay below .kuzushi: {}",
        path.display()
    );
    Ok(relative)
}

pub(super) fn validate_run_id(run_id: &str) -> Result<()> {
    anyhow::ensure!(
        !run_id.is_empty() && run_id.len() <= 128,
        "vendor-assessment runId must contain between 1 and 128 characters"
    );
    let mut characters = run_id.chars();
    anyhow::ensure!(
        characters
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric()),
        "vendor-assessment runId must start with an ASCII letter or digit"
    );
    anyhow::ensure!(
        characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        }),
        "vendor-assessment runId may contain only ASCII letters, digits, '.', '-', and '_'"
    );
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
