use super::*;
use kuzushi_core::V2Config;

#[test]
fn tools_model_lists_registry_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = tools_model(&app);

    assert!(model.total_count >= model.rows.len());
    assert_eq!(model.filter, None);
    assert!(model.rows.iter().any(|row| row.cells[0] == "sast:scan"));
    assert!(model.rows.iter().all(|row| !row.cells[1].is_empty()));
}

#[test]
fn tools_model_filters_by_query_tokens() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tools_filter = Some("semgrep scan".to_string());

    let model = tools_model(&app);

    assert_eq!(model.filter.as_deref(), Some("semgrep scan"));
    assert!(model.rows.iter().any(|row| row.cells[0] == "semgrep:scan"));
    assert!(model.rows.iter().all(|row| {
        let text = format!("{} {}", row.cells[0], row.cells[1]).to_ascii_lowercase();
        text.contains("semgrep") && text.contains("scan")
    }));
    assert!(model.rows.len() < model.total_count);
}

#[test]
fn tools_model_preserves_empty_filtered_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tools_filter = Some("not-a-real-tool-token".to_string());

    let model = tools_model(&app);

    assert!(model.rows.is_empty());
    assert!(model.total_count > 0);
}
