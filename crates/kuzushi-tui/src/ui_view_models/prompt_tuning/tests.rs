use super::*;
use kuzushi_core::V2Config;
use std::fs;

#[test]
fn tune_model_shapes_default_module_actions_and_empty_rules() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.tune_cursor = 1;

    let model = tune_model(&app, 4);

    assert_eq!(model.module, "semgrep");
    assert_eq!(model.house_rules_path, ".kuzushi/house-rules/semgrep.md");
    assert_eq!(model.severity_floor, "medium");
    assert_eq!(model.triage_confidence, "0.70");
    assert_eq!(model.scan_concurrency, "adaptive");
    assert_eq!(model.house_rules, TuneHouseRules::Empty);
    assert_eq!(model.actions.len(), 3);
    assert!(model.actions[1].selected);
    assert_eq!(model.actions[1].label, "edit house rules (set \"...\")");
}

#[test]
fn tune_model_reads_limited_house_rules() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.target = Some(temp.path().to_path_buf());
    app.focused_module = Some("sast".to_string());
    let rules = temp.path().join(".kuzushi/house-rules/sast.md");
    fs::create_dir_all(rules.parent().unwrap()).unwrap();
    fs::write(&rules, "auth only\nno generated code\nthird line").unwrap();

    let model = tune_model(&app, 2);

    assert_eq!(
        model.house_rules,
        TuneHouseRules::Present(vec![
            "auth only".to_string(),
            "no generated code".to_string()
        ])
    );
}

#[test]
fn prompts_model_shapes_prompt_rows_for_focused_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.focused_module = Some("sast".to_string());
    app.prompts_cursor = 2;

    let model = prompts_model(&app);

    assert_eq!(model.module, "sast");
    assert_eq!(model.rows[0].path, ".kuzushi/prompts/sast/scan.md");
    assert_eq!(model.rows[2].verb, "verify");
    assert!(model.rows[2].selected);
}
