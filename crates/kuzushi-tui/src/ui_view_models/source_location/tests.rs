use super::*;
use kuzushi_core::{Finding, Severity, V2Config};

#[test]
fn ordinary_locations_stay_compact_and_line_ranges_remain_outside_quotes() {
    assert_eq!(
        source_location_label("src/main.rs", Some(4), Some(7), None),
        "src/main.rs:4-7"
    );
    assert_eq!(
        source_location_label("src/main.rs", None, None, None),
        "src/main.rs"
    );
    assert_eq!(
        source_location_label("src/main.rs", Some(4), Some(2), None),
        "src/main.rs:4"
    );
    assert_eq!(
        source_location_label(" app /lib.py", Some(2), Some(4), None),
        "\" app /lib.py\":2-4"
    );
    assert_eq!(
        source_location_label("app/lib.py:7", Some(2), None, None),
        "\"app/lib.py:7\":2"
    );
}

#[test]
fn quoted_display_round_trips_literal_whitespace_controls_and_punctuation() {
    for path in [
        " app /lib.py",
        "app/lib.py ",
        "src/a  b.rs",
        "src/\"name\".rs",
        "src/a\\b.rs",
        "src/new\nline.rs",
        "src/escape\u{1b}.rs",
        "src/日本 語.rs",
    ] {
        let label = source_path_label(path, None);
        assert_eq!(serde_json::from_str::<String>(&label).unwrap(), path);
        assert!(!label.chars().any(char::is_control));
    }
    assert_eq!(source_path_label("src/a,b.rs", None), "src/a,b.rs");
}

#[test]
fn relativizing_uses_directory_membership_and_never_a_shared_string_prefix() {
    let target = tempfile::tempdir().unwrap();
    let base = target.path().to_str().unwrap();
    let file = target.path().join(" app ").join("lib.py");
    let sibling = format!("{base}-other/src/lib.rs");
    assert_eq!(
        relative_source_path(file.to_str().unwrap(), Some(base)),
        format!(" app {}lib.py", std::path::MAIN_SEPARATOR)
    );
    assert_eq!(
        source_path_label(file.to_str().unwrap(), Some(base)),
        serde_json::Value::String(format!(" app {}lib.py", std::path::MAIN_SEPARATOR)).to_string()
    );
    assert_eq!(relative_source_path(&sibling, Some(base)), sibling);
}

#[test]
fn review_list_detail_and_raw_export_keep_two_distinct_literal_paths() {
    let mut app = crate::ShellApp::new(V2Config::default(), None);
    let files = [" app /lib.py", "app/lib.py"];
    let findings = files
        .iter()
        .map(|path| {
            Finding::new_tool(
                "semgrep",
                "owned-policy",
                *path,
                2,
                None,
                Severity::Info,
                "Owned policy note",
            )
        })
        .collect();
    app.set_findings(findings);
    let original = serde_json::to_value(app.findings()).unwrap();
    let list = crate::ui_view_models::findings::findings_model(&app);
    assert_eq!(list.rows.len(), 2);
    assert!(list
        .rows
        .iter()
        .any(|row| row.location == "\" app /lib.py\":2"));
    assert!(list.rows.iter().any(|row| row.location == "app/lib.py:2"));
    let queue = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::All,
    );
    assert!(queue
        .rows
        .iter()
        .any(|row| row.location == "\" app /lib.py\":2"));
    let selected = crate::ui_view_models::findings::projected_visible_findings(&app)
        .iter()
        .position(|row| row.finding.file_path == files[0])
        .unwrap();
    app.router.findings_mut().set_cursor(selected);
    let detail = crate::ui_view_models::selected_finding_detail_model(&app).unwrap();
    assert_eq!(detail.location, "\" app /lib.py\":2");
    let preview = super::super::report_preview::report_preview_model(
        &app,
        kuzushi_core::WorkspaceExportFormat::Json,
        crate::ui_view_models::ReviewQueueMode::All,
    );
    assert!(preview
        .rows
        .iter()
        .any(|row| row.location == "\" app /lib.py\":2"));
    assert!(preview
        .rows
        .iter()
        .any(|row| row.location == "app/lib.py:2"));
    assert_eq!(serde_json::to_value(app.findings()).unwrap(), original);
    for finding in app.findings() {
        assert_eq!(
            kuzushi_core::finding_location(finding),
            format!("{}:2", finding.file_path)
        );
        assert!(files.contains(&finding.file_path.as_str()));
    }
}
