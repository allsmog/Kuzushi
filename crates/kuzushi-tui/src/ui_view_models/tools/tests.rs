use super::*;
use kuzushi_core::V2Config;

#[test]
fn tools_model_lists_registry_tools() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = tools_model(&app);

    assert!(model.rows.iter().any(|row| row.cells[0] == "sast:scan"));
    assert!(model.rows.iter().all(|row| !row.cells[2].is_empty()));
}
