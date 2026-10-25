use super::*;

fn historical_app() -> (tempfile::TempDir, ShellApp, Finding) {
    let (root, mut app) = scanned_fold_app();
    let mut historical = scanned_fold_finding();
    historical.id = Some(1);
    historical.identity_id = Some("owned-history-identity".into());
    historical.scan_id = Some("earlier".into());
    let mut current = historical.clone();
    current.id = Some(2);
    current.scan_id = Some("later".into());
    app.set_findings(vec![current]);
    (root, app, historical)
}

#[test]
fn historical_observation_uses_retained_bytes_even_when_live_focus_matches() {
    let (_root, app, historical) = historical_app();
    store_live_source(&app, &historical, Ok("let x = 2;\n"));
    store_scanned_window(
        &app,
        &historical,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["let x = 2;".into()],
        }),
    );
    let snippet = source_snippet_model(&app, &historical).unwrap();
    assert_eq!(snippet.lines, ["let x = 2;"]);
    assert_eq!(snippet.retained_run_checkout.as_deref(), Some("unknown"));
}

#[test]
fn historical_observation_without_retained_bytes_does_not_show_current_source() {
    let (_root, app, historical) = historical_app();
    store_live_source(&app, &historical, Ok("CURRENT CHECKOUT\n"));
    store_scanned_window(&app, &historical, crate::ScannedSnippetState::Missing);
    let snippet = source_snippet_model(&app, &historical).unwrap();
    assert!(snippet.lines.is_empty());
    assert_eq!(
        snippet.note.as_deref(),
        Some("Retained source unavailable for this observation")
    );
}

#[test]
fn historical_observation_does_not_flash_current_source_before_hydration() {
    let (_root, app, historical) = historical_app();
    store_live_source(&app, &historical, Ok("CURRENT CHECKOUT\n"));
    let snippet = source_snippet_model(&app, &historical).unwrap();
    assert!(snippet.lines.is_empty());
    assert_eq!(
        snippet.note.as_deref(),
        Some("Retained source not available yet for this observation")
    );
}

#[test]
fn matching_citation_with_changed_neighboring_context_uses_retained_excerpt() {
    let (_root, app) = scanned_fold_app();
    let mut finding = scanned_fold_finding();
    finding.start_line = 2;
    store_live_source(&app, &finding, Ok("// later context\nlet x = 2;\n"));
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 2,
            lines: vec!["// earlier context".into(), "let x = 2;".into()],
        }),
    );
    let snippet = source_snippet_model(&app, &finding).unwrap();
    assert_eq!(snippet.lines[0], "// earlier context");
    assert_eq!(snippet.retained_run_checkout.as_deref(), Some("unknown"));
    assert!(snippet.note.is_none());
}

#[test]
fn current_file_preview_discloses_an_absent_retained_copy() {
    let (_root, app) = scanned_fold_app();
    let finding = scanned_fold_finding();
    store_live_source(&app, &finding, Ok("current bytes\n"));
    store_scanned_window(&app, &finding, crate::ScannedSnippetState::Missing);
    let snippet = source_snippet_model(&app, &finding).unwrap();
    assert_eq!(snippet.lines, ["current bytes"]);
    assert_eq!(
        snippet.note.as_deref(),
        Some("current file preview · no scanned copy recorded")
    );
}

#[test]
fn current_file_preview_does_not_imply_recorded_source_before_hydration() {
    let (_root, app) = scanned_fold_app();
    let finding = scanned_fold_finding();
    store_live_source(&app, &finding, Ok("current bytes\n"));
    let snippet = source_snippet_model(&app, &finding).unwrap();
    assert_eq!(snippet.lines, ["current bytes"]);
    assert_eq!(
        snippet.note.as_deref(),
        Some("current file preview · retained observation source not checked")
    );
}

#[test]
fn indentation_changes_are_source_changes() {
    let (_root, app) = scanned_fold_app();
    let finding = scanned_fold_finding();
    store_live_source(&app, &finding, Ok("allow()\n"));
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["    allow()".into()],
        }),
    );
    let snippet = source_snippet_model(&app, &finding).unwrap();
    assert_eq!(snippet.lines, ["    allow()"]);
    assert_eq!(snippet.retained_run_checkout.as_deref(), Some("unknown"));
    assert!(snippet.note.is_none());
}

#[test]
fn saved_generation_keeps_retained_source_without_a_current_list_counterpart() {
    let (_root, app) = scanned_fold_app();
    let mut finding = scanned_fold_finding();
    finding.id = Some(42);
    store_live_source(&app, &finding, Ok("identical bytes\n"));
    store_scanned_window(
        &app,
        &finding,
        crate::ScannedSnippetState::Ready(crate::ScannedSnippetWindow {
            start_line: 1,
            focus_line: 1,
            lines: vec!["identical bytes".into()],
        }),
    );
    let snippet = source_snippet_model(&app, &finding).unwrap();
    assert_eq!(snippet.lines, ["identical bytes"]);
    assert_eq!(snippet.retained_run_checkout.as_deref(), Some("unknown"));
    assert!(snippet.note.is_none());
}
