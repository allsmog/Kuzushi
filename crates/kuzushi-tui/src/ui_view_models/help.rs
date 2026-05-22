use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpModel {
    pub(crate) intro: &'static str,
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
    pub(crate) text: &'static str,
}

pub(crate) fn help_model() -> HelpModel {
    HelpModel {
        intro: "Input: ? opens help; ?text, /ask <question>, and ask <question> enter agent mode.",
        examples: shell_help_examples().to_vec(),
        categories: ShellCommandCategory::ORDER
            .iter()
            .map(|category| help_category_model(*category))
            .collect(),
    }
}

pub(crate) fn plain_help_model() -> PlainHelpModel {
    PlainHelpModel::from_help_model(help_model())
}

impl PlainHelpModel {
    fn from_help_model(model: HelpModel) -> Self {
        PlainHelpModel {
            title: "HELP",
            intro: model.intro,
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
    (!examples.is_empty()).then(|| format!("Examples: {}", examples.join(" | ")))
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

fn help_category_model(category: ShellCommandCategory) -> HelpCategoryModel {
    HelpCategoryModel {
        label: category.label(),
        blurb: help_category_blurb(category),
        commands: shell_command_specs()
            .filter(|spec| spec.category == category)
            .map(help_command_row)
            .collect(),
    }
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
        QuickstartStep {
            number: "1",
            text: "kuzushi doctor             CLI preflight (run from your terminal, not here)",
        },
        QuickstartStep {
            number: "2",
            text: "onboarding (or context build)  multi-select planner: context / x-ray / STRIDE / PASTA / CPG / CodeQL / threat intel",
        },
        QuickstartStep {
            number: "3",
            text: quickstart_scan_step(app),
        },
        QuickstartStep {
            number: "4",
            text: "run <tool>                 dispatch a single tool (e.g. run semgrep:scan)",
        },
        QuickstartStep {
            number: "5",
            text: "findings · open F-0001     inspect evidence and proof state",
        },
        QuickstartStep {
            number: "6",
            text: "workspace export findings  write a report; kuzushi pr-comment for PR drop",
        },
    ]
}

fn quickstart_scan_step(app: &ShellApp) -> &'static str {
    if app.target.is_some() {
        "scan                       scan the active target with configured scanners"
    } else {
        "scan .                     scan the current directory (the dot is cwd)"
    }
}

#[cfg(test)]
mod tests;
