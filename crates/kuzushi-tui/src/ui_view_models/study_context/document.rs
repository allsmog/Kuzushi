use super::*;

pub(crate) fn context_summary(document: &Value) -> Vec<String> {
    let mut lines = text_fields(document, &["title"]);
    lines.extend(verification::lines(document));
    lines.extend(text_fields(
        document,
        &["systemContext", "description", "context"],
    ));
    for (label, pointer) in [
        ("Components", "/dfd/nodes"),
        ("Data flows", "/dfd/flows"),
        ("Trust boundaries", "/dfd/trustBoundaries"),
        ("Threats", "/threats"),
        ("Open questions", "/openQuestions"),
    ] {
        lines.extend(context_section(label, document.pointer(pointer)));
    }
    lines.extend(evidence::receipt_lines(document));
    lines.extend(super::super::evidence_inventory::filename_receipt_lines(
        document.pointer("/provenance/repositoryInventory"),
    ));
    lines
}

fn text_fields(document: &Value, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|key| document.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn context_section(label: &str, value: Option<&Value>) -> Vec<String> {
    let rows = value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut lines = vec![format!("{label}: {}", rows.len())];
    lines.extend(rows.iter().map(|row| format!("  {}", context_item(row))));
    lines
}

fn context_item(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.into();
    }
    let title = ["title", "name", "question", "id"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str));
    let description = value.get("description").and_then(Value::as_str);
    let answer = value
        .get("answer")
        .and_then(Value::as_str)
        .map(|answer| format!("Answer: {answer}"));
    let mut text = [title, description]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    if let Some(answer) = answer {
        text.push_str(&format!(" · {answer}"));
    }
    text
}
