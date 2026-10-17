use super::storage::{proposed_scope, resolve_input_path, save_scope};
use crate::capabilities::vendor_assessment::domain::AttachmentInput;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) fn attach(root: &Path, input: AttachmentInput) -> Result<Value> {
    proposed_scope(root, &input.scope_update).and_then(|mut scope| {
        attachment_document(root, input).and_then(|doc| {
            append_document(&mut scope, doc.clone())?;
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
        "id": format!("doc-{}", uuid::Uuid::new_v4().simple()),
        "source": input.source,
        "kind": input.kind,
        "title": title,
        "status": content.status,
        "text": content.text,
        "parseWarnings": content.warnings,
        "sourceBytes": content.source_bytes,
        "capturedBytes": content.captured_bytes,
        "storedTextBytes": content.text.len(),
        "textTruncated": content.truncated,
        "sourceDigest": content.source_digest,
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
    source_bytes: Option<usize>,
    captured_bytes: usize,
    truncated: bool,
    source_digest: Option<String>,
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
        source_bytes: None, captured_bytes: 0, truncated: false, source_digest: None,
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
    let mut content = content_from_bytes(&raw);
    content.source_bytes = Some(raw.len());
    content.source_digest = Some(crate::run_lifecycle::sha256_content_digest(&raw));
    Ok(content)
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
        source_bytes: None,
        captured_bytes: 0,
        truncated: false,
        source_digest: None,
        warnings: vec!["Attachment looks binary; stored metadata without parsed text.".to_string()],
    }
}

fn text_attachment_content(raw: &[u8]) -> AttachmentContent {
    let (text, captured_bytes, lossy) = captured_text(raw);
    let truncated = captured_bytes < raw.len();
    let mut warnings = Vec::new();
    if truncated {
        warnings.push(format!(
            "Text capture is partial: {captured_bytes} of {} source bytes retained.",
            raw.len()
        ));
    }
    if lossy {
        warnings.push("Invalid UTF-8 was replaced in the stored text.".into());
    }
    AttachmentContent {
        status: "attached".to_string(),
        text,
        warnings,
        source_bytes: None,
        captured_bytes,
        truncated,
        source_digest: None,
    }
}

fn captured_text(raw: &[u8]) -> (String, usize, bool) {
    let mut end = raw.len().min(256_000);
    match std::str::from_utf8(raw) {
        Ok(text) => {
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            (text[..end].into(), end, false)
        }
        Err(_) => (String::from_utf8_lossy(&raw[..end]).into_owned(), end, true),
    }
}

fn append_document(scope: &mut Value, doc: Value) -> Result<()> {
    let documents = scope
        .as_object_mut()
        .context("vendor scope must be an object")?
        .entry("documents")
        .or_insert_with(|| json!([]));
    documents
        .as_array_mut()
        .context("vendor scope documents must be an array")?
        .push(doc);
    Ok(())
}

fn attach_response(scope: Value, doc: Value, scope_path: PathBuf) -> Value {
    let summary = capture_summary(&doc);
    let mut output = summary.clone();
    let warnings = doc["parseWarnings"].as_array().cloned().unwrap_or_default();
    for warning in &warnings {
        output.push_str(&format!(
            "\n{}",
            warning.as_str().unwrap_or("Evidence capture warning")
        ));
    }
    output.push_str(&format!("\nDraft scope: {}", scope_path.display()));
    let mut result = crate::module_result::completed_output_result(
        summary,
        output,
        json!({
            "scope": scope,
            "document": doc,
            "scopePath": scope_path.display().to_string(),
        }),
    );
    result["warnings"] = json!(warnings);
    result
}

fn capture_summary(doc: &Value) -> String {
    let title = doc["title"].as_str().unwrap_or("document");
    if doc["status"] == "referenced" {
        return format!("Referenced {title}; document not fetched.");
    }
    if doc["textTruncated"] == true {
        return format!(
            "Attached {title}: text prefix only ({}/{} bytes).",
            doc["capturedBytes"], doc["sourceBytes"]
        );
    }
    format!(
        "Attached {title} ({}).",
        if doc["storedTextBytes"] == 0 {
            "metadata only"
        } else {
            "text captured"
        }
    )
}
