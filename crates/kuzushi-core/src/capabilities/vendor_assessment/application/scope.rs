use super::prompt_bundle::build_prompt_bundle;
use super::storage::{load_updated_scope, runs_dir, save_scope, scope_path};
use crate::capabilities::vendor_assessment::domain::{empty_scope, unix_millis, ScopeUpdate};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn scope(root: &Path, update: ScopeUpdate, clear: bool) -> Result<Value> {
    if clear {
        return clear_scope(root);
    }
    update_scope(root, update)
}

fn clear_scope(root: &Path) -> Result<Value> {
    let scope = empty_scope();
    let scope_path = save_scope(root, &scope)?;
    Ok(crate::module_result::completed_output_result(
        "Vendor assessment draft scope cleared.",
        "Vendor assessment draft scope cleared.",
        json!({
            "cleared": true,
            "scope": scope,
            "scopePath": scope_path.display().to_string(),
        }),
    ))
}

fn update_scope(root: &Path, update: ScopeUpdate) -> Result<Value> {
    load_updated_scope(root, &update).map(|scope| {
        let docs = document_count(&scope);
        scope_response(scope, scope_path(root), docs)
    })
}

fn document_count(scope: &Value) -> usize {
    scope
        .get("documents")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn scope_response(scope: Value, scope_path: PathBuf, docs: usize) -> Value {
    let output = format!(
        "Vendor assessment scope\n  Vendor: {}\n  Product: {}\n  Documents: {}\n  Scope: {}",
        scope.get("vendorName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
        scope.get("productName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
        docs,
        scope_path.display(),
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "scope": scope,
            "scopePath": scope_path.display().to_string(),
        }),
    )
}

pub(crate) fn prompts(root: &Path, update: ScopeUpdate, run_id: Option<String>) -> Result<Value> {
    load_updated_scope(root, &update).and_then(|scope| {
        let run_id = run_id.unwrap_or_else(|| format!("prompts-{}", unix_millis()));
        let prompts_dir = runs_dir(root).join(&run_id).join("prompts");
        write_prompt_bundle(&prompts_dir, &scope)
            .map(|prompts| prompts_response(run_id, prompts_dir, prompts, &scope))
    })
}

fn write_prompt_bundle(prompts_dir: &Path, scope: &Value) -> Result<Vec<(String, String)>> {
    ensure_prompt_dir(prompts_dir).and_then(|_| {
        let prompts = build_prompt_bundle(&scope);
        write_prompt_files(prompts_dir, &prompts).map(|_| prompts)
    })
}

fn ensure_prompt_dir(prompts_dir: &Path) -> Result<()> {
    fs::create_dir_all(prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))
}

fn write_prompt_files(prompts_dir: &Path, prompts: &[(String, String)]) -> Result<()> {
    prompts.iter().try_for_each(|(filename, content)| {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))
            .with_context(|| format!("Could not write {}", prompts_dir.join(filename).display()))
    })
}

fn prompts_response(
    run_id: String,
    prompts_dir: PathBuf,
    prompts: Vec<(String, String)>,
    scope: &Value,
) -> Value {
    let output = format!(
        "Prompt bundle written to {}\nProfile: {}\nPrompts: {}",
        prompts_dir.display(),
        scope.get("profile").and_then(Value::as_str).unwrap_or("enterprise-ai"),
        prompts.len()
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "runId": run_id,
            "promptsDir": prompts_dir.display().to_string(),
            "prompts": prompts.iter().map(|(file, content)| json!({"fileName": file, "content": content})).collect::<Vec<_>>(),
        }),
    );
    result["artifacts"] = json!([{ "label": "prompts", "path": prompts_dir.display().to_string() }]);
    result
}
