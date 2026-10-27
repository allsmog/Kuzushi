use super::*;

#[test]
fn finding_location_keeps_distinct_service_prefixes_and_complete_filenames() {
    for width in [24, 28, 40, 60] {
        let labels = ["services/a", "services/b"].map(|prefix| {
            let value = format!("{prefix}/{}f064.py:2", "deep/".repeat(40));
            let label = fit_location_label(&value, width);
            assert!(label.starts_with(prefix), "{width}: {label}");
            assert!(label.ends_with("/f064.py:2"), "{width}: {label}");
            assert!(display_width(&label) <= width);
            label
        });
        assert_ne!(labels[0], labels[1]);
    }
}

#[test]
fn finding_location_preserves_fitting_literals_and_line_ranges() {
    for value in [
        "src/code.rs:2-4",
        r#""services/a\\name/file name.rs":2-4"#,
        "界/e\u{301}.rs:42",
    ] {
        assert_eq!(fit_location_label(value, display_width(value)), value);
    }
    let value = format!(
        r#""services/a\\name/{}file name.rs":2-4"#,
        "deep/".repeat(12)
    );
    let label = fit_location_label(&value, 48);
    assert!(label.starts_with(r#""services/a\\name/"#));
    assert!(label.ends_with(r#"/file name.rs":2-4"#));
}

#[test]
fn finding_location_respects_every_small_column_budget_and_graphemes() {
    for value in [
        "界界/e\u{301}/very-long-source-name.rs:42",
        "root-file-with-a-long-name.rs:2",
        "👩‍💻/日本/very-long-source-name.rs:2",
    ] {
        for width in 0..80 {
            let label = fit_location_label(value, width);
            assert!(display_width(&label) <= width, "{width}: {label}");
            assert!(!label.starts_with('\u{301}') && !label.ends_with('\u{200d}'));
        }
    }
    assert!(fit_location_label("src/file.rs:2", 0).is_empty());
    assert_eq!(
        fit_location_label("root-file-with-a-long-name.rs:42", 2),
        "42"
    );
}

#[test]
fn compact_finding_preview_uses_the_same_location_policy() {
    let location = format!("services/a/{}f064.py:2", "deep/".repeat(40));
    let row = super::super::compact_finding_row(
        "F-0001",
        "INFO",
        crate::ui_view_models::SeverityTone::Info,
        "Owner policy",
        &location,
        80,
    );
    let text = row
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert!(text.contains("services/a/") && text.ends_with("f064.py:2"));
    assert!(row.width() <= 80);
}
