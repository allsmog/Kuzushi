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
        .any(|row| row.cells[1].contains("/h")));
}

#[test]
fn plain_help_model_projects_plain_rows() {
    let model = plain_help_model();

    assert_eq!(model.title, "HELP");
    assert!(model.intro.contains("? opens help"));
    let examples = model.examples_line.as_deref().unwrap_or_default();
    assert!(examples.starts_with("Examples: "));
    assert!(examples.contains("scan ."));
    assert!(examples.contains("run ."));
    assert!(examples.contains("model 1"));
    assert!(model
        .categories
        .iter()
        .any(|category| category.heading == "NAVIGATION — browse modules and tools"));
    assert!(model
        .categories
        .iter()
        .flat_map(|category| category.rows.iter())
        .any(|row| row.starts_with("  aliases / examples:") && row.contains("/h")));
}

#[test]
fn quickstart_model_uses_current_target_scan_shape() {
    // M1 §1.2: the Quickstart now has an explicit `target` step at index 1
    // (numbered 2), which shifts scan/context to the indexes below.
    let mut app = ShellApp::new(V2Config::default(), None);

    let no_target = quickstart_model(&app);

    let scan_step = no_target
        .steps
        .iter()
        .find(|step| step.text.contains("scan"))
        .expect("scan step present");
    assert!(scan_step.text.starts_with("scan . / run"));
    assert!(no_target.first_finding_tip.contains("`scan .`"));
    assert!(no_target
        .steps
        .iter()
        .any(|step| step.text.contains("target <path>")));

    app.target = Some(PathBuf::from("."));
    let with_target = quickstart_model(&app);

    let scan_step = with_target
        .steps
        .iter()
        .find(|step| step.text.starts_with("scan / run"))
        .expect("scan step present when target set");
    assert!(scan_step.text.starts_with("scan / run"));
    assert!(with_target.first_finding_tip.contains("`scan`"));
}
