use super::*;
use std::collections::BTreeSet;

const MAX_CONTEXT_FIELDS: usize = 8;
const MAX_VALUE_LINES: usize = 4;
const MAX_LINE_CHARACTERS: usize = 240;

pub(super) fn changed_document_sections(before: &Value, after: &Value) -> Vec<String> {
    before
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .chain(
            after
                .as_object()
                .into_iter()
                .flat_map(|object| object.keys()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect()
}

pub(super) fn section_labels(sections: &[String]) -> String {
    if sections.is_empty() {
        "none".into()
    } else {
        sections.join(", ")
    }
}

pub(super) fn render_context_changes(changes: &[ContextTextDifference]) -> Vec<String> {
    let mut lines = vec![format!("context text: {} change(s)", changes.len())];
    for change in changes.iter().take(MAX_CONTEXT_FIELDS) {
        lines.push(format!("{} · {}", change.label, change.pointer));
        lines.extend(value_preview("Before", &change.before));
        lines.extend(value_preview("After", &change.after));
    }
    if !changes.is_empty() {
        lines.push("Preview: up to 8 fields, 4 lines per value, 240 characters per line. Full values are in result.contextText.".into());
    }
    lines
}

fn value_preview(label: &str, value: &str) -> Vec<String> {
    if value.is_empty() {
        return vec![format!("  {label}: (empty)")];
    }
    std::iter::once(format!("  {label}:"))
        .chain(value.lines().take(MAX_VALUE_LINES).map(|line| {
            let preview = line.chars().take(MAX_LINE_CHARACTERS).collect::<String>();
            format!("    {preview}")
        }))
        .collect()
}

#[cfg(test)]
mod tests;
