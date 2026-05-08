use super::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct ScopeUpdate {
    pub(crate) vendor_name: Option<String>,
    pub(crate) product_name: Option<String>,
    pub(crate) primary_domain: Option<String>,
    pub(crate) use_case: Option<String>,
    pub(crate) profile: Option<String>,
    pub(crate) data_classes: Option<Vec<String>>,
    pub(crate) integrations: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct AttachmentInput {
    pub(crate) source: String,
    pub(crate) kind: String,
    pub(crate) title: Option<String>,
    pub(crate) scope_update: ScopeUpdate,
}

pub(crate) fn empty_scope() -> Value {
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

pub(crate) fn merge_scope_inputs(mut scope: Value, update: &ScopeUpdate) -> Value {
    let Value::Object(ref mut object) = scope else {
        return empty_scope();
    };
    insert_string_update(object, "vendorName", &update.vendor_name);
    insert_string_update(object, "productName", &update.product_name);
    insert_string_update(object, "primaryDomain", &update.primary_domain);
    insert_string_update(object, "useCase", &update.use_case);
    insert_string_update(object, "profile", &update.profile);
    insert_array_update(object, "dataClasses", &update.data_classes);
    insert_array_update(object, "integrations", &update.integrations);
    object.insert("updatedAt".to_string(), json!(unix_millis()));
    scope
}

fn insert_string_update(object: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

fn insert_array_update(object: &mut Map<String, Value>, key: &str, value: &Option<Vec<String>>) {
    if let Some(value) = value {
        object.insert(key.to_string(), json!(value));
    }
}

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
    let raw = fs::read(&path).with_context(|| {
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
    json!({
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
    })
}
