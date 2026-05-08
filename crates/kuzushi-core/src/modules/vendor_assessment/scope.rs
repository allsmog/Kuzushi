use super::*;

pub(in crate::modules) fn scope(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    if read_bool_any(&input, &["clear"])?.unwrap_or(false) {
        let scope = empty_scope();
        let scope_path = save_scope(&root, &scope)?;
        return Ok(json!({
            "ok": true,
            "output": "Vendor assessment draft scope cleared.",
            "data": {
                "cleared": true,
                "scope": scope,
                "scopePath": scope_path.display().to_string(),
            },
        }));
    }
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    let scope_path = save_scope(&root, &scope)?;
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment scope\n  Vendor: {}\n  Product: {}\n  Documents: {}\n  Scope: {}",
            scope.get("vendorName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            scope.get("productName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            docs,
            scope_path.display(),
        ),
        "data": {
            "scope": scope,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}

pub(in crate::modules) fn prompts(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    save_scope(&root, &scope)?;
    let run_id = string_input_any(&input, &["runId", "run_id"])
        .unwrap_or_else(|| format!("prompts-{}", unix_millis()));
    let prompts_dir = runs_dir(&root).join(&run_id).join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))
            .with_context(|| format!("Could not write {}", prompts_dir.join(filename).display()))?;
    }
    Ok(json!({
        "ok": true,
        "output": format!(
            "Prompt bundle written to {}\nProfile: {}\nPrompts: {}",
            prompts_dir.display(),
            scope.get("profile").and_then(Value::as_str).unwrap_or("enterprise-ai"),
            prompts.len()
        ),
        "data": {
            "runId": run_id,
            "promptsDir": prompts_dir.display().to_string(),
            "prompts": prompts.iter().map(|(file, content)| json!({"fileName": file, "content": content})).collect::<Vec<_>>(),
        },
    }))
}
