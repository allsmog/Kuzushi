use super::*;

#[test]
fn a_selected_overview_changes_the_scanner_digest_without_other_sections() {
    let app = render_threat_model_digest(&json!({"systemContext":"App-specific source guidance"}))
        .unwrap();
    let other =
        render_threat_model_digest(&json!({"systemContext":"Other source guidance"})).unwrap();
    assert!(app.contains("System overview:\n- App-specific source guidance"));
    assert_ne!(app, other);
}

#[test]
fn overview_selection_uses_text_fields_and_canonical_precedence() {
    let document =
        json!({"systemContext":"  Canonical overview  ","system_context":"Legacy overview"});
    assert_eq!(
        select_threat_digest_overview(&document),
        Some("Canonical overview")
    );
    for primary in [
        json!(null),
        json!({"instruction":"unselected"}),
        json!(["unselected"]),
        json!(" "),
    ] {
        let document = json!({"systemContext":primary,"system_context":"Legacy overview"});
        assert_eq!(
            select_threat_digest_overview(&document),
            Some("Legacy overview")
        );
    }
    assert!(render_threat_model_digest(
        &json!({"title":"Metadata only","description":"Unselected root prose"})
    )
    .is_none());
}

#[test]
fn long_overview_preserves_unicode_and_respects_the_existing_field_ceiling() {
    let overview = format!("{}OMITTED_TAIL", "界".repeat(MAX_DIGEST_FIELD_CHARS));
    let document = json!({"systemContext":overview});
    let before = document.clone();
    let text = render_threat_model_digest(&document).unwrap();
    assert_eq!(
        text,
        format!(
            "System overview:\n- {}...",
            "界".repeat(MAX_DIGEST_FIELD_CHARS)
        )
    );
    assert_eq!(document, before);
}
