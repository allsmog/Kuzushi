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
    assert!(all_tool_rows(&model)
        .iter()
        .all(|row| row.cells[0] != "fuzz:run"));
    assert!(app.registry().resolve_tool("fuzz:run").is_some());
    assert!(model
        .groups
        .iter()
        .any(|group| group.label == "SCAN"
            && group.rows.iter().any(|row| row.cells[0] == "sast:scan")));
    assert!(all_tool_rows(&model)
        .iter()
        .all(|row| !row.cells[1].is_empty()));
    assert!(all_tool_rows(&model)
        .iter()
        .all(|row| !row.cells[2].is_empty()));
}

#[test]
fn tools_model_groups_follow_canonical_phase_order() {
    let app = ShellApp::new(V2Config::default(), None);
    let model = tools_model(&app);
    let labels: Vec<&str> = model.groups.iter().map(|group| group.label).collect();

    // Phase groups appear in canonical MAP→SCAN→REVIEW→PROVE→FIX→OPERATE order,
    // filtering to the non-empty subset.
    let order = ["MAP", "SCAN", "REVIEW", "PROVE", "FIX", "OPERATE"];
    let positions: Vec<usize> = labels
        .iter()
        .filter_map(|label| order.iter().position(|o| o == label))
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(positions, sorted, "phase groups out of canonical order");
}

#[test]
fn tools_model_filters_by_fuzzy_free_text() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.tools_mut().open(Some("semgrep".to_string()));

    let model = tools_model(&app);

    assert_eq!(model.filter.as_deref(), Some("semgrep"));
    let rows = all_tool_rows(&model);
    assert!(rows.iter().any(|row| row.cells[0] == "semgrep:scan"));
    assert!(model.visible_count < model.total_count);
}

#[test]
fn tools_model_filters_by_phase_key() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.tools_mut().open(Some("phase:hunt".to_string()));

    let model = tools_model(&app);

    // The deprecated phase:hunt query resolves to the canonical SCAN group.
    assert!(model
        .groups
        .iter()
        .all(|group| group.label == "SCAN" || group.label == YOUR_TOOLS_LABEL));
    assert!(model
        .groups
        .iter()
        .any(|group| group.label == "SCAN" && !group.rows.is_empty()));
}

#[test]
fn tools_model_unknown_key_yields_no_rows() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.tools_mut().open(Some("bogus:value".to_string()));

    let model = tools_model(&app);

    assert_eq!(model.visible_count, 0);
    assert!(model.groups.is_empty());
    assert!(model.total_count > 0);
}

#[test]
fn tools_model_preserves_empty_filtered_state() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router
        .tools_mut()
        .open(Some("zzzznotarealtooltoken".to_string()));

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
