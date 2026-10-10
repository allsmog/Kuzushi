use super::*;

#[test]
fn changed_sections_include_removed_and_explicit_null_fields() {
    let before = json!({"systemContext":"Alpha","metadata":{"source":"old"},"optional":null});
    let after = json!({"systemContext":"Alpha","metadata":{"source":"new"}});
    assert_eq!(
        changed_document_sections(&before, &after),
        vec!["metadata", "optional"]
    );
    assert_eq!(section_labels(&[]), "none");
}

#[test]
fn terminal_preview_is_bounded_but_does_not_modify_complete_values() {
    let changes = (0..10)
        .map(|index| ContextTextDifference {
            pointer: format!("/field/{index}"),
            label: format!("Field {index}"),
            before: String::new(),
            after: (0..9)
                .map(|_| "α".repeat(300))
                .collect::<Vec<_>>()
                .join("\n"),
        })
        .collect::<Vec<_>>();
    let lines = render_context_changes(&changes);
    assert!(lines[0].contains("10 change(s)"));
    assert!(lines.iter().any(|line| line.contains("Full values")));
    assert!(!lines.iter().any(|line| line.contains("Field 8")));
    assert!(lines
        .iter()
        .all(|line| line.chars().count() <= MAX_LINE_CHARACTERS + 4));
    assert_eq!(changes[0].after.lines().count(), 9);
    assert_eq!(
        changes[0].after.lines().next().unwrap().chars().count(),
        300
    );
}
