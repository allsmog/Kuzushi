use super::storage::{load_updated_scope, resolve_input_path, save_scope};
use crate::capabilities::vendor_assessment::domain::{unix_millis, AttachmentInput};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) fn attach(root: &Path, input: AttachmentInput) -> Result<Value> {
    load_updated_scope(root, &input.scope_update).and_then(|mut scope| {
        attachment_document(root, input).and_then(|doc| {
            append_document(&mut scope, doc.clone());
            save_scope(root, &scope).map(|scope_path| attach_response(scope, doc, scope_path))
        })
    })
}

fn attachment_document(root: &Path, input: AttachmentInput) -> Result<Value> {
    let title = input
        .title
        .unwrap_or_else(|| default_attachment_title(&input.source));
    let content = attachment_content(root, &input.source)?;
    Ok(json!({
        "id": format!("doc-{}", unix_millis()),
        "source": input.source,
        "kind": input.kind,
        "title": title,
        "status": content.status,
        "text": content.text,
        "parseWarnings": content.warnings,
    }))
}

fn default_attachment_title(source: &str) -> String {
    Path::new(source)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(source)
        .to_string()
}

struct AttachmentContent {
    status: String,
    text: String,
    warnings: Vec<String>,
}

fn attachment_content(root: &Path, source: &str) -> Result<AttachmentContent> {
    if is_remote_source(source) {
        return Ok(remote_attachment_content());
    }
    local_attachment_content(root, source)
}

fn is_remote_source(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

fn remote_attachment_content() -> AttachmentContent {
    AttachmentContent {
        status: "referenced".to_string(),
        text: String::new(),
        warnings: vec![
            "Rust vendor-assessment records URL evidence but does not fetch remote documents; download the document locally and pass source/path to parse text.".to_string(),
        ],
    }
}

fn local_attachment_content(root: &Path, source: &str) -> Result<AttachmentContent> {
    let path = resolve_input_path(root, source);
    let raw =
        crate::bounded_file::read_regular_bytes(&path, 32 * 1024 * 1024).with_context(|| {
            format!(
                "Could not read vendor assessment attachment {}",
                path.display()
            )
        })?;
    Ok(content_from_bytes(&raw))
}

fn content_from_bytes(raw: &[u8]) -> AttachmentContent {
    if looks_binary(raw) {
        return binary_attachment_content();
    }
    text_attachment_content(raw)
}

fn looks_binary(raw: &[u8]) -> bool {
    raw.iter().take(4096).any(|byte| *byte == 0)
}

fn binary_attachment_content() -> AttachmentContent {
    AttachmentContent {
        status: "attached".to_string(),
        text: String::new(),
        warnings: vec!["Attachment looks binary; stored metadata without parsed text.".to_string()],
    }
}

fn text_attachment_content(raw: &[u8]) -> AttachmentContent {
    AttachmentContent {
        status: "attached".to_string(),
        text: String::from_utf8_lossy(&raw[..raw.len().min(256_000)]).to_string(),
        warnings: Vec::new(),
    }
}

fn append_document(scope: &mut Value, doc: Value) {
    let documents = scope
        .as_object_mut()
        .expect("vendor scope is an object")
        .entry("documents")
        .or_insert_with(|| json!([]));
    append_to_array(documents, doc);
}

fn append_to_array(value: &mut Value, item: Value) {
    if let Some(items) = value.as_array_mut() {
        items.push(item);
    }
}

fn attach_response(scope: Value, doc: Value, scope_path: PathBuf) -> Value {
    let output = format!(
        "Attached {} ({})\nScope: {}",
        doc.get("title")
            .and_then(Value::as_str)
            .unwrap_or("document"),
        doc.get("status")
            .and_then(Value::as_str)
            .unwrap_or("attached"),
        scope_path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "scope": scope,
            "document": doc,
            "scopePath": scope_path.display().to_string(),
        }),
    )
}
