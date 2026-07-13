use crate::app::rank_fuzzy;
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpModel {
    pub(crate) intro: &'static str,
    pub(crate) glossary: &'static str,
    pub(crate) filter_note: Option<String>,
    pub(crate) examples: Vec<&'static str>,
    pub(crate) categories: Vec<HelpCategoryModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpCategoryModel {
    pub(crate) label: &'static str,
    pub(crate) blurb: &'static str,
    pub(crate) commands: Vec<HelpCommandRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpCommandRow {
    pub(crate) cells: [String; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainHelpModel {
    pub(crate) title: &'static str,
    pub(crate) intro: &'static str,
    pub(crate) glossary: &'static str,
    pub(crate) filter_note: Option<String>,
    pub(crate) examples_line: Option<String>,
    pub(crate) categories: Vec<PlainHelpCategoryModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainHelpCategoryModel {
    pub(crate) heading: String,
    pub(crate) rows: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuickstartModel {
    pub(crate) steps: Vec<QuickstartStep>,
    pub(crate) first_finding_tip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuickstartStep {
    pub(crate) number: &'static str,
    pub(crate) text: String,
}

pub(crate) fn help_model(query: Option<&str>) -> HelpModel {
    let query = normalized_help_query(query);
    HelpModel {
        intro: "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode.",
        glossary: "Glossary: TP=true positive; FP=false positive; DFD=data-flow diagram; taint-iris=source-to-sink hunt; x-ray=architecture review; randori=threat model; tob/shinsa=plugin adapters.",
        filter_note: query.map(|value| {
            format!("Showing commands matching `{value}`. Type `help` for the full reference.")
        }),
        examples: query
            .is_none()
            .then(|| shell_help_examples().to_vec())
            .unwrap_or_default(),
        categories: ShellCommandCategory::ORDER
            .iter()
            .filter_map(|category| help_category_model(*category, query))
            .collect(),
    }
}

pub(crate) fn plain_help_model(query: Option<&str>) -> PlainHelpModel {
    PlainHelpModel::from_help_model(help_model(query))
}

impl PlainHelpModel {
    fn from_help_model(model: HelpModel) -> Self {
        PlainHelpModel {
            title: "HELP",
            intro: model.intro,
            glossary: model.glossary,
            filter_note: model.filter_note,
            examples_line: plain_examples_line(&model.examples),
            categories: model
                .categories
                .into_iter()
                .map(plain_help_category)
                .collect(),
        }
    }
}

fn plain_examples_line(examples: &[&'static str]) -> Option<String> {
    (!examples.is_empty()).then(|| format!("Examples: {}", examples.join("  ·  ")))
}

fn plain_help_category(category: HelpCategoryModel) -> PlainHelpCategoryModel {
    PlainHelpCategoryModel {
        heading: format!("{} — {}", category.label, category.blurb),
        rows: category
            .commands
            .into_iter()
            .flat_map(plain_help_command_rows)
            .collect(),
    }
}

fn plain_help_command_rows(row: HelpCommandRow) -> Vec<String> {
    let command = &row.cells[0];
    let aliases = &row.cells[1];
    let description = &row.cells[2];
    let mut rows = vec![format!("{command} - {description}")];
    if aliases != "-" {
        rows.push(format!("  aliases / examples: {aliases}"));
    }
    rows
}

pub(crate) fn quickstart_model(app: &ShellApp) -> QuickstartModel {
    QuickstartModel {
        steps: quickstart_steps(app),
        first_finding_tip: format!(
            "First-finding path: `{}` then `findings`.",
            app.first_finding_scan_command()
        ),
    }
}

fn help_category_model(
    category: ShellCommandCategory,
    query: Option<&str>,
) -> Option<HelpCategoryModel> {
    let specs = shell_command_specs()
        .filter(|spec| spec.category == category)
        .collect::<Vec<_>>();
    let commands = filtered_help_specs(specs, query)
        .into_iter()
        .map(help_command_row)
        .collect::<Vec<_>>();
    (!commands.is_empty()).then(|| HelpCategoryModel {
        label: category.label(),
        blurb: help_category_blurb(category),
        commands,
    })
}

fn normalized_help_query(query: Option<&str>) -> Option<&str> {
    query.map(str::trim).filter(|value| !value.is_empty())
}

fn filtered_help_specs(
    specs: Vec<&'static ShellCommandSpec>,
    query: Option<&str>,
) -> Vec<&'static ShellCommandSpec> {
    let Some(query) = query else {
        return specs;
    };
    let entries = specs
        .into_iter()
        .map(|spec| (help_search_key(spec), spec))
        .collect::<Vec<_>>();
    let ranked = rank_fuzzy(entries.iter().map(|(key, _)| key.clone()).collect(), query);
    ranked
        .into_iter()
        .filter_map(|key| {
            entries
                .iter()
                .find_map(|(candidate, spec)| (candidate == &key).then_some(*spec))
        })
        .collect()
}

fn help_search_key(spec: &ShellCommandSpec) -> String {
    let aliases = spec.aliases.join(" ");
    format!("{} {aliases} {}", spec.command, spec.description)
}

fn help_category_blurb(category: ShellCommandCategory) -> &'static str {
    match category {
        ShellCommandCategory::Navigation => "browse modules and tools",
        ShellCommandCategory::RunScan => "dispatch tools and scans",
        ShellCommandCategory::OptionsTasks => "options + sast task control",
        ShellCommandCategory::ContextKb => "workspace + attachments",
        ShellCommandCategory::FindingsEvidence => "browse findings, evidence, and report output",
        ShellCommandCategory::AuthConfigModel => "auth, model, runtime config",
        ShellCommandCategory::Session => "history, cost, lifecycle",
    }
}

fn help_command_row(spec: &ShellCommandSpec) -> HelpCommandRow {
    HelpCommandRow {
        cells: [
            spec.command.to_string(),
            help_alias_text(spec),
            spec.description.to_string(),
        ],
    }
}

fn help_alias_text(spec: &ShellCommandSpec) -> String {
    let mut aliases = Vec::new();
    for alias in spec.aliases {
        if *alias == spec.command || aliases.contains(alias) {
            continue;
        }
        aliases.push(*alias);
    }
    if aliases.is_empty() {
        "-".to_string()
    } else {
        aliases.join(", ")
    }
}

fn quickstart_steps(app: &ShellApp) -> Vec<QuickstartStep> {
    vec![
        quickstart_step("1", quickstart_target_step(app)),
        quickstart_step(
            "2",
            "doctor                     check scanners, runtime, and credentials here",
        ),
        quickstart_step(
            "3",
            "model                      choose a model; use auth to connect, or demo to stay offline",
        ),
        quickstart_step(
            "4",
            "next                       open the current phase planner; Space toggles tasks, Enter runs",
        ),
        quickstart_step(
            "5",
            "findings                   review results in the Workbench queue",
        ),
        quickstart_step(
            "6",
            "open F-0001                inspect evidence, proof state, and the next action",
        ),
        quickstart_step(
            "7",
            "verify F-0001              collect stronger proof before remediation",
        ),
        quickstart_step(
            "8",
            "findings export report.sarif sarif  write a shareable report",
        ),
    ]
}

fn quickstart_step(number: &'static str, text: impl Into<String>) -> QuickstartStep {
    QuickstartStep {
        number,
        text: text.into(),
    }
}

fn quickstart_target_step(app: &ShellApp) -> &'static str {
    if app.target().is_some() {
        "target                     confirm the active target before spending tools"
    } else {
        "target .                   set cwd as target, or use target <path>"
    }
}

#[cfg(test)]
mod tests;
