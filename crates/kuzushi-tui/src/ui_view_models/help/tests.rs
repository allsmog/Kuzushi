use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn help_model_projects_registered_examples_and_aliases() {
    let model = help_model();

    assert!(model.intro.contains("? opens help"));
    assert!(model.examples.contains(&"run ."));
    assert!(model
        .categories
        .iter()
        .any(|category| category.blurb == "browse modules and tools"));
    assert!(model
        .categories
        .iter()
        .flat_map(|category| category.commands.iter())
        .any(|row| row.aliases.contains("/h")));
}

#[test]
fn quickstart_model_uses_current_target_scan_shape() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let no_target = quickstart_model(&app);

    assert!(no_target.steps[2].text.starts_with("scan . / run"));
    assert!(no_target.first_finding_tip.contains("`scan .`"));

    app.target = Some(PathBuf::from("."));
    let with_target = quickstart_model(&app);

    assert!(with_target.steps[2].text.starts_with("scan / run"));
    assert!(with_target.first_finding_tip.contains("`scan`"));
}
