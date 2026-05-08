use super::*;

pub(in crate::modules) fn empty_scope() -> Value {
    json!({
        "version": "1",
        "vendorName": "",
        "productName": "",
        "primaryDomain": "",
        "useCase": "",
        "profile": "enterprise-ai",
        "dataClasses": [],
        "integrations": [],
        "documents": [],
        "updatedAt": unix_millis(),
    })
}

pub(in crate::modules) fn merge_scope_inputs(mut scope: Value, input: &Value) -> Value {
    let Value::Object(ref mut object) = scope else {
        return empty_scope();
    };
    for (input_keys, output_key) in [
        (&["vendorName", "vendor"][..], "vendorName"),
        (&["productName"][..], "productName"),
        (&["primaryDomain", "domain"][..], "primaryDomain"),
        (&["useCase"][..], "useCase"),
        (&["profile"][..], "profile"),
    ] {
        if let Some(value) = string_input_any(input, input_keys) {
            object.insert(output_key.to_string(), json!(value));
        }
    }
    for key in ["dataClasses", "integrations"] {
        if let Some(values) = string_array_or_csv_input(input, &[key]) {
            object.insert(key.to_string(), json!(values));
        }
    }
    object.insert("updatedAt".to_string(), json!(unix_millis()));
    scope
}

pub(in crate::modules) fn attach(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let source = string_input_any(&input, &["source", "path", "url", "target"])
        .context("vendor-assessment:attach requires source, path, url, or target")?;
    let mut scope = merge_scope_inputs(load_scope(&root)?, &input);
    let kind = string_input_any(&input, &["kind"]).unwrap_or_else(|| "other".to_string());
    let title = string_input_any(&input, &["title"]).unwrap_or_else(|| {
        Path::new(&source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&source)
            .to_string()
    });
    let (status, text, warnings) = if source.starts_with("http://")
        || source.starts_with("https://")
    {
        (
            "referenced".to_string(),
            String::new(),
            vec![
                "Rust vendor-assessment records URL evidence but does not fetch remote documents; download the document locally and pass source/path to parse text.".to_string(),
            ],
        )
    } else {
        let path = resolve_input_path(&root, &source);
        let raw = fs::read(&path).with_context(|| {
            format!(
                "Could not read vendor assessment attachment {}",
                path.display()
            )
        })?;
        if raw.iter().take(4096).any(|byte| *byte == 0) {
            (
                "attached".to_string(),
                String::new(),
                vec!["Attachment looks binary; stored metadata without parsed text.".to_string()],
            )
        } else {
            let text = String::from_utf8_lossy(&raw[..raw.len().min(256_000)]).to_string();
            ("attached".to_string(), text, Vec::new())
        }
    };
    let doc = json!({
        "id": format!("doc-{}", unix_millis()),
        "source": source,
        "kind": kind,
        "title": title,
        "status": status,
        "text": text,
        "parseWarnings": warnings,
    });
    let documents = scope
        .as_object_mut()
        .expect("vendor scope is an object")
        .entry("documents")
        .or_insert_with(|| json!([]));
    if let Some(items) = documents.as_array_mut() {
        items.push(doc.clone());
    }
    let scope_path = save_scope(&root, &scope)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Attached {} ({})\nScope: {}",
            doc.get("title").and_then(Value::as_str).unwrap_or("document"),
            doc.get("status").and_then(Value::as_str).unwrap_or("attached"),
            scope_path.display()
        ),
        "data": {
            "scope": scope,
            "document": doc,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}
