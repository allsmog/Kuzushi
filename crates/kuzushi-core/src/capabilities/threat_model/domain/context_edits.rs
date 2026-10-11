//! Text edits are bound to one immutable document and cannot alter evidence metadata.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
mod comparison;

pub const MAX_CONTEXT_EDIT_BYTES: usize = 16 * 1024;
pub const MAX_CONTEXT_EDITS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextTextEdit {
    pub pointer: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextTextField {
    pub pointer: String,
    pub label: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextTextDifference {
    pub pointer: String,
    pub label: String,
    pub before: String,
    pub after: String,
}

pub fn context_text_differences(before: &Value, after: &Value) -> Vec<ContextTextDifference> {
    comparison::compare_context_text(before, after)
}

pub fn context_text_fields(document: &Value) -> Vec<ContextTextField> {
    let mut fields = vec![text_field(
        document,
        "/systemContext".into(),
        "System overview".into(),
    )];
    append_component_fields(document, &mut fields);
    append_question_fields(document, &mut fields);
    fields
}

fn text_field(document: &Value, pointer: String, label: String) -> ContextTextField {
    let text = document
        .pointer(&pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    ContextTextField {
        pointer,
        label,
        text,
    }
}

fn append_component_fields(document: &Value, fields: &mut Vec<ContextTextField>) {
    for (index, node) in rows(document, "/dfd/nodes").iter().enumerate() {
        if !node.is_object() {
            continue;
        }
        let name = node
            .get("name")
            .or_else(|| node.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("Component");
        for (key, title) in [("description", "Description"), ("purpose", "Purpose")] {
            fields.push(text_field(
                document,
                format!("/dfd/nodes/{index}/{key}"),
                format!("{name} · {title}"),
            ));
        }
    }
}

fn append_question_fields(document: &Value, fields: &mut Vec<ContextTextField>) {
    for (index, question) in rows(document, "/openQuestions").iter().enumerate() {
        if !(question.is_object() || question.is_string()) {
            continue;
        }
        let title = question_title(question);
        fields.push(text_field(
            document,
            format!("/openQuestions/{index}/answer"),
            format!("Answer {} · {title}", index + 1),
        ));
    }
}

fn question_title(question: &Value) -> &str {
    question
        .as_str()
        .or_else(|| {
            question
                .get("question")
                .or_else(|| question.get("description"))
                .and_then(Value::as_str)
        })
        .unwrap_or("Open question")
}

fn rows<'a>(document: &'a Value, pointer: &str) -> &'a [Value] {
    document
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

pub fn apply_context_text_edits(document: &Value, edits: &[ContextTextEdit]) -> Result<Value> {
    anyhow::ensure!(
        !edits.is_empty() && edits.len() <= MAX_CONTEXT_EDITS,
        "Supply 1 to {MAX_CONTEXT_EDITS} context text edits"
    );
    let fields = context_text_fields(document)
        .into_iter()
        .map(|field| (field.pointer, field.text))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut revised = document.clone();
    for edit in edits {
        validate_text_edit(edit, &fields, &mut seen)?;
        apply_changed_text(&mut revised, edit, &fields)?;
    }
    anyhow::ensure!(
        revised != *document,
        "No context text changed; keep the existing revision"
    );
    Ok(revised)
}

fn apply_changed_text(
    document: &mut Value,
    edit: &ContextTextEdit,
    fields: &BTreeMap<String, String>,
) -> Result<()> {
    if fields.get(&edit.pointer) == Some(&edit.text) {
        return Ok(());
    }
    replace_text(document, edit)
}

fn validate_text_edit(
    edit: &ContextTextEdit,
    fields: &BTreeMap<String, String>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    anyhow::ensure!(
        fields.contains_key(&edit.pointer),
        "This context field is not editable: {}",
        edit.pointer
    );
    anyhow::ensure!(
        seen.insert(edit.pointer.clone()),
        "Duplicate context edit: {}",
        edit.pointer
    );
    anyhow::ensure!(
        edit.text.len() <= MAX_CONTEXT_EDIT_BYTES,
        "Context text exceeds {MAX_CONTEXT_EDIT_BYTES} bytes"
    );
    anyhow::ensure!(
        !edit.text.contains('\0'),
        "Context text cannot contain a NUL character"
    );
    Ok(())
}

fn replace_text(document: &mut Value, edit: &ContextTextEdit) -> Result<()> {
    let (parent, key) = edit
        .pointer
        .rsplit_once('/')
        .context("Invalid context field")?;
    let object = text_parent(document, parent)?;
    if edit.text.is_empty() {
        object.remove(key);
    } else {
        object.insert(key.into(), Value::String(edit.text.clone()));
    }
    Ok(())
}

fn text_parent<'a>(
    document: &'a mut Value,
    pointer: &str,
) -> Result<&'a mut serde_json::Map<String, Value>> {
    let parent = document
        .pointer_mut(pointer)
        .context("Context field parent is missing")?;
    if let Some(question) = parent.as_str() {
        *parent = serde_json::json!({"question":question});
    }
    parent
        .as_object_mut()
        .context("Context field parent is not an object")
}

#[cfg(test)]
mod tests;
