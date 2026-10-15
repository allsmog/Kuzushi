use super::*;

#[test]
fn failed_scope_cause_precedes_planning_terms_at_every_required_width() {
    let root = tempfile::tempdir().unwrap();
    let mut config = BatchScanConfig::load(root.path(), None);
    config.context_generation = Some(StudyContextGeneration {
        generation_tool: Some("pack:suggest-scopes".into()),
        result_error: Some("Scope proposal rejected: unknown shared dependency greeting".into()),
        ..Default::default()
    });
    for width in [40, 60, 80, 96, 120, 160] {
        let lines = summary(&config, width);
        let text = lines.join(" ");
        assert!(text.find("greeting").unwrap() < text.find("One scope proposal job").unwrap());
        assert!(
            lines
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("Scope proposal rejected"),
            "{width}: {lines:?}"
        );
        assert!(
            text.contains("separate approval") && text.contains("No automatic repair or rerun")
        );
    }
}

#[test]
fn absent_scope_form_has_no_work_or_planning_copy() {
    let root = tempfile::tempdir().unwrap();
    let config = BatchScanConfig::load(root.path(), None);
    assert!(summary(&config, 80).is_empty());
}
