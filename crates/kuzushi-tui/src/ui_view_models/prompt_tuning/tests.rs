use super::*;
use kuzushi_core::V2Config;
use std::fs;

fn house_rule_path(root: &std::path::Path) -> std::path::PathBuf {
    kuzushi_core::house_rule_path(root, "sast")
}

fn relative_house_rule_path(module: &str) -> String {
    kuzushi_core::relative_house_rule_path(module)
        .display()
        .to_string()
}

fn relative_prompt_override_path(module: &str, verb: &str) -> String {
    kuzushi_core::relative_prompt_override_path(module, verb)
        .display()
        .to_string()
}

#[test]
fn tune_model_shapes_default_module_actions_and_empty_rules() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.router.tune_mut().set_cursor(1);

    let model = tune_model(&app, 4);

    assert_eq!(model.module, "semgrep");
    assert_eq!(model.house_rules_path, relative_house_rule_path("semgrep"));
    assert_eq!(model.severity_floor, "medium");
    assert_eq!(model.triage_confidence, "0.70");
    assert_eq!(model.scan_concurrency, "adaptive");
    assert_eq!(model.house_rules, TuneHouseRules::Empty);
    assert_eq!(model.actions.len(), 3);
    assert!(model.actions[1].selected);
    assert_eq!(model.actions[1].label, "edit house rules (set \"...\")");
}

#[test]
fn tune_model_uses_limited_cached_house_rules() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    app.router
        .tune_mut()
        .set_house_rules(HouseRulesRead::Present(
            "auth only\nno generated code\nthird line".to_string(),
        ));

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
fn tune_model_surfaces_cached_unreadable_house_rules() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    let rules = house_rule_path(temp.path());
    app.router
        .tune_mut()
        .set_house_rules(HouseRulesRead::Unreadable(rules.clone()));

    let model = tune_model(&app, 2);

    assert_eq!(
        model.house_rules,
        TuneHouseRules::Unreadable(rules.display().to_string())
    );
}

#[test]
fn prompts_model_shapes_prompt_rows_for_focused_module() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_focused_module(Some("sast".to_string()));
    app.router.prompts_mut().set_cursor(2);

    let model = prompts_model(&app);

    assert_eq!(model.module, "sast");
    assert_eq!(model.rows[0].source, "no target");
    assert_eq!(
        model.rows[0].path,
        relative_prompt_override_path("sast", "scan")
    );
    assert_eq!(model.rows[2].verb, "verify");
    assert!(model.rows[2].selected);
    assert_eq!(model.stack.verb, "verify");
    assert_eq!(model.stack.layers[1].state, "no target");
    assert_eq!(model.stack.layers[5].state, "base active");
}

#[test]
fn prompts_model_builds_stack_for_selected_project_override() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.router.prompts_mut().set_cursor(1);
    let override_path = kuzushi_core::prompt_override_path(temp.path(), "sast", "triage");
    fs::create_dir_all(override_path.parent().unwrap()).unwrap();
    fs::write(&override_path, "focus on auth bypass\n").unwrap();

    let model = prompts_model(&app);
    let expected_hash = kuzushi_core::prompt_content_sha256("focus on auth bypass\n");

    assert_eq!(model.stack.verb, "triage");
    assert_eq!(model.rows[1].source, "file");
    assert_eq!(model.stack.layers.len(), 6);
    assert_eq!(model.stack.layers[0].layer, "base");
    assert_eq!(model.stack.layers[1].layer, "project override");
    assert_eq!(model.stack.layers[1].state, "present");
    assert_eq!(
        model.stack.layers[1].path,
        relative_prompt_override_path("sast", "triage")
    );
    assert_eq!(model.stack.layers[1].hash, expected_hash);
    assert_eq!(model.stack.layers[3].layer, "mutation");
    assert_eq!(model.stack.layers[3].state, "inactive");
    assert_eq!(model.stack.layers[5].layer, "final");
    assert_eq!(model.stack.layers[5].state, "override active");
    assert_eq!(
        model.stack.layers[5].hash,
        kuzushi_core::prompt_content_sha256("focus on auth bypass\n")
    );
}

#[test]
fn prompts_model_blocks_final_stack_for_pending_mutation_until_approved() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_focused_module(Some("sast".to_string()));
    app.router.prompts_mut().set_cursor(1);
    let mutation =
        kuzushi_core::PromptMutation::new("sast", "triage", "focus authz paths", "operator");
    let expected_hash = mutation.content_hash();
    kuzushi_core::append_prompt_mutation(&workspace, &mutation).unwrap();

    let pending = prompts_model(&app);

    assert_eq!(pending.stack.layers[3].layer, "mutation");
    assert_eq!(pending.stack.layers[3].state, "pending approval");
    assert_eq!(pending.stack.layers[3].hash, expected_hash);
    assert_eq!(pending.stack.layers[5].layer, "final");
    assert_eq!(
        pending.stack.layers[5].state,
        "blocked: mutation pending approval"
    );

    kuzushi_core::set_prompt_mutation_status(
        &workspace,
        &mutation.id,
        kuzushi_core::PromptMutationStatus::Approved,
        Some("reviewed"),
    )
    .unwrap();
    let approved = prompts_model(&app);

    assert_eq!(approved.stack.layers[3].state, "approved");
    assert_eq!(approved.stack.layers[5].state, "approved mutation active");
    assert_eq!(approved.stack.layers[5].hash, expected_hash);
}
