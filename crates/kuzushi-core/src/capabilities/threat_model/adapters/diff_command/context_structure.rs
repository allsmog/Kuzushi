use super::*;

pub(super) fn render(diff: &ContextDocumentDiff) -> Vec<String> {
    let mut lines = vec![format!(
        "stored structure: {} field change(s), {} collection order change(s)",
        diff.changes.len(),
        diff.reordered_collections.len()
    )];
    for change in diff.changes.iter().take(8) {
        lines.push(format!(
            "{} · id={} · field={} · matching={:?}",
            change.collection.as_deref().unwrap_or("document"),
            json!(change.identity),
            json!(change.field),
            change.matching
        ));
        lines.extend(value_preview("Before", change.before.as_ref()));
        lines.extend(value_preview("After", change.after.as_ref()));
    }
    lines.push("Preview: up to 8 fields, 4 lines per value, 240 characters per line. Full values, pointers, ordering and saved source claims are in data.contextStructure. Matching saved claims do not verify current source or finding verdicts.".into());
    lines
}

fn value_preview(label: &str, value: Option<&Value>) -> Vec<String> {
    let value = value.map_or_else(
        || "(not present)".into(),
        |value| serde_json::to_string_pretty(value).expect("JSON values serialize"),
    );
    std::iter::once(format!("  {label}:"))
        .chain(
            value
                .lines()
                .take(4)
                .map(|line| format!("    {}", line.chars().take(240).collect::<String>())),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_preview_is_bounded_but_full_values_and_null_remain_in_data() {
        let before = json!({"metadata":{}});
        let after = json!({"metadata":{"empty":null,"long":"α".repeat(2000)}});
        let diff = context_document_differences(&before, &after);
        let rendered = render(&diff).join("\n");
        assert!(rendered.contains("(not present)"));
        assert!(rendered.contains("    null"));
        assert!(rendered.contains("data.contextStructure"));
        assert!(!rendered.contains(&"α".repeat(241)));
        assert_eq!(diff.changes[1].after, Some(json!("α".repeat(2000))));
    }
}
