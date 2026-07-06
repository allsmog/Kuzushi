use super::*;
use kuzushi_core::V2Config;

#[test]
fn tools_model_lists_registry_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = tools_model(&app);

    assert!(model.total_count >= model.visible_count);
    assert_eq!(model.filter, None);
    assert!(all_tool_rows(&model)
        .iter()
        .any(|row| row.cells[0] == "sast:scan"));
    assert!(model
        .groups
        .iter()
        .any(|group| group.label == "HUNT"
            && group.rows.iter().any(|row| row.cells[0] == "sast:scan")));
    assert!(all_tool_rows(&model)
        .iter()
        .all(|row| !row.cells[1].is_empty()));
    assert!(all_tool_rows(&model)
        .iter()
        .all(|row| !row.cells[2].is_empty()));
}

#[test]
fn tools_model_filters_by_query_tokens() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .tools_mut()
        .open(Some("semgrep scan".to_string()));

    let model = tools_model(&app);

    assert_eq!(model.filter.as_deref(), Some("semgrep scan"));
    let rows = all_tool_rows(&model);
    assert!(rows.iter().any(|row| row.cells[0] == "semgrep:scan"));
    assert!(rows.iter().all(|row| {
        let text = format!("{} {}", row.cells[0], row.cells[1]).to_ascii_lowercase();
        text.contains("semgrep") && text.contains("scan")
    }));
    assert!(model.visible_count < model.total_count);
}

#[test]
fn tools_model_preserves_empty_filtered_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .tools_mut()
        .open(Some("not-a-real-tool-token".to_string()));

    let model = tools_model(&app);

    assert_eq!(model.visible_count, 0);
    assert!(model.groups.is_empty());
    assert!(model.total_count > 0);
}

fn all_tool_rows(model: &ToolsModel) -> Vec<&ToolRow> {
    model
        .groups
        .iter()
        .flat_map(|group| group.rows.iter())
        .collect()
}
