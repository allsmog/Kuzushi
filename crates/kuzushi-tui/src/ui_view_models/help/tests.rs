use super::*;
use kuzushi_core::V2Config;
use std::path::PathBuf;

#[test]
fn help_model_projects_registered_examples_and_aliases() {
    let model = help_model(None);

    assert!(model.intro.contains("? opens help"));
    assert!(model.glossary.contains("taint-iris=source-to-sink"));
    assert!(model.glossary.contains("randori=threat model"));
    assert!(model.examples.contains(&"full ."));
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
    let model = plain_help_model(None);

    assert_eq!(model.title, "HELP");
    assert!(model.intro.contains("? opens help"));
    let examples = model.examples_line.as_deref().unwrap_or_default();
    assert!(examples.starts_with("Examples: "));
    assert!(examples.contains("kuzushi scan <target>"));
    assert!(examples.contains("kuzushi --target <target> run sast:scan"));
    assert!(!examples.contains("full ."));
    assert!(examples.contains("findings export report.sarif sarif"));
    assert!(model
        .categories
        .iter()
        .any(|category| category.heading == "NAVIGATION — browse modules and tools"));
    assert!(model
        .categories
        .iter()
        .flat_map(|category| category.rows.iter())
        .any(|row| row.starts_with("  aliases / examples:") && row.contains("/h")));
    assert!(model
        .categories
        .iter()
        .flat_map(|category| category.rows.iter())
        .any(|row| row.starts_with("target rev <ref> -")));
    assert!(model
        .categories
        .iter()
        .flat_map(|category| category.rows.iter())
        .any(|row| row.starts_with("full [target] - interactive TUI only")));
}

#[test]
fn help_model_filters_commands_by_query() {
    let model = help_model(Some("scan"));

    assert!(model
        .filter_note
        .as_deref()
        .unwrap_or_default()
        .contains("scan"));
    assert!(model.examples.is_empty());
    let rows = model
        .categories
        .iter()
        .flat_map(|category| category.commands.iter())
        .collect::<Vec<_>>();
    assert!(!rows.is_empty());
    assert!(rows.iter().any(|row| row.cells[0] == "scan"));
    assert!(rows.iter().any(|row| row.cells[0] == "full [target]"));
    assert!(!rows.iter().any(|row| row.cells[0] == "scan [target]"));
    assert!(!rows.iter().any(|row| row.cells[0] == "story"));
}

#[test]
fn exact_command_query_promotes_the_canonical_command_and_keeps_fuzzy_search() {
    let full = help_model(Some("full"));
    let first = &full.categories[0].commands[0];

    assert_eq!(first.cells[0], "full [target]");
    assert!(first.cells[1].contains("pipeline [target]"));

    let planner = help_model(Some("planner"));
    let planner_commands = planner
        .categories
        .iter()
        .flat_map(|category| category.commands.iter())
        .map(|row| row.cells[0].as_str())
        .collect::<Vec<_>>();
    assert!(planner_commands.contains(&"map"));
    assert!(planner_commands.contains(&"scan"));
}

#[test]
fn quickstart_model_uses_current_target_scan_shape() {
    let mut app = ShellApp::new(V2Config::default(), None);

    let no_target = quickstart_model(&app);

    assert!(no_target.steps[0].text.starts_with("target ."));
    assert!(no_target.steps[1].text.starts_with("doctor"));
    assert!(no_target.steps[2].text.starts_with("model"));
    assert!(no_target.steps[3].text.starts_with("next"));
    assert!(no_target.first_finding_tip.contains("`target .; next`"));

    app.set_target(Some(PathBuf::from(".")));
    let with_target = quickstart_model(&app);

    assert!(with_target.steps[0].text.starts_with("target "));
    assert!(with_target.steps[3].text.starts_with("next"));
    assert!(with_target.first_finding_tip.contains("`next`"));
}
