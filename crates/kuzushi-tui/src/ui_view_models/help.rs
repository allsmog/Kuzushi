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
    pub(crate) command: &'static str,
    pub(crate) aliases: String,
    pub(crate) description: &'static str,
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
        command: spec.command,
        aliases: help_alias_text(spec),
        description: spec.description,
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
            text: "doctor                    CLI preflight: kuzushi doctor",
        },
        QuickstartStep {
            number: "2",
            text: "context build              write .kuzushi/context-snapshot.json",
        },
        QuickstartStep {
            number: "3",
            text: quickstart_scan_step(app),
        },
        QuickstartStep {
            number: "4",
            text: "findings / open F-0001     inspect evidence and proof state",
        },
        QuickstartStep {
            number: "5",
            text: "report output              workspace export; kuzushi pr-comment",
        },
    ]
}

fn quickstart_scan_step(app: &ShellApp) -> &'static str {
    if app.target.is_some() {
        "scan / run                 scan the active target; run <tool> dispatches one tool"
    } else {
        "scan . / run <tool>        scan this directory; run <tool> dispatches one tool"
    }
}

#[cfg(test)]
mod tests;
