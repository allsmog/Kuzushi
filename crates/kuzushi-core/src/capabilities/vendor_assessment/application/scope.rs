use super::prompt_bundle::build_prompt_bundle;
use super::storage::{
    load_updated_scope, prepare_state_path, runs_dir, save_scope, scope_path, validate_run_id,
    write_state_path,
};
use crate::capabilities::vendor_assessment::domain::{empty_scope, unix_millis, ScopeUpdate};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) fn scope(root: &Path, update: ScopeUpdate, clear: bool) -> Result<Value> {
    if clear {
        anyhow::ensure!(
            update.is_empty(),
            "clear cannot be combined with vendor scope updates; existing scope was preserved"
        );
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
        "Vendor assessment scope\n  Vendor: {}\n  Product: {}\n  Profile: {}\n  Documents: {}\n  Scope: {}",
        scope
            .get("vendorName")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or("(unset)"),
        scope
            .get("productName")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .unwrap_or("(unset)"),
        scope.get("profile").and_then(Value::as_str).unwrap_or("(unset)"),
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
    let run_id = run_id.unwrap_or_else(|| format!("prompts-{}", unix_millis()));
    validate_run_id(&run_id)?;
    let prompts_dir = runs_dir(root).join(&run_id).join("prompts");
    for filename in [
        "overview.md",
        "evidence-review.md",
        "follow-up-questions.md",
    ] {
        prepare_state_path(root, &prompts_dir.join(filename))?;
    }
    load_updated_scope(root, &update).and_then(|scope| {
        write_prompt_bundle(root, &prompts_dir, &scope)
            .map(|prompts| prompts_response(run_id, prompts_dir, prompts, &scope))
    })
}

fn write_prompt_bundle(
    root: &Path,
    prompts_dir: &Path,
    scope: &Value,
) -> Result<Vec<(String, String)>> {
    let prompts = build_prompt_bundle(&scope);
    write_prompt_files(root, prompts_dir, &prompts).map(|_| prompts)
}

fn write_prompt_files(root: &Path, prompts_dir: &Path, prompts: &[(String, String)]) -> Result<()> {
    for (filename, _) in prompts {
        prepare_state_path(root, &prompts_dir.join(filename))?;
    }
    prompts.iter().try_for_each(|(filename, content)| {
        let path = prompts_dir.join(filename);
        write_state_path(root, &path, format!("{content}\n").as_bytes()).map(|_| ())
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
        scope
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or("enterprise-ai"),
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
    result["artifacts"] =
        json!([{ "label": "prompts", "path": prompts_dir.display().to_string() }]);
    result
}
