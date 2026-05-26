use crate::{HouseRulesRead, ShellApp, TuneAction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuneModel {
    pub(crate) module: String,
    pub(crate) severity_floor: &'static str,
    pub(crate) triage_confidence: &'static str,
    pub(crate) scan_concurrency: &'static str,
    pub(crate) house_rules_path: String,
    pub(crate) actions: Vec<TuneActionRow>,
    pub(crate) house_rules: TuneHouseRules,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TuneActionRow {
    pub(crate) label: &'static str,
    pub(crate) hint: &'static str,
    pub(crate) selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TuneHouseRules {
    Present(Vec<String>),
    Unreadable(String),
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptsModel {
    pub(crate) module: String,
    pub(crate) rows: Vec<PromptRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptRow {
    pub(crate) verb: &'static str,
    pub(crate) source: &'static str,
    pub(crate) path: String,
    pub(crate) selected: bool,
}

pub(crate) fn tune_model(app: &ShellApp, house_rule_limit: usize) -> TuneModel {
    let module = focused_module(app);
    TuneModel {
        house_rules_path: kuzushi_core::relative_house_rule_path(&module)
            .display()
            .to_string(),
        actions: tune_action_rows(app),
        house_rules: house_rules(app, house_rule_limit),
        module,
        severity_floor: "medium",
        triage_confidence: "0.70",
        scan_concurrency: "adaptive",
    }
}

pub(crate) fn prompts_model(app: &ShellApp) -> PromptsModel {
    let module = focused_module(app);
    let cursor = app.prompts_cursor_clamped();
    let rows = ShellApp::PROMPT_VERB_NAMES
        .iter()
        .enumerate()
        .map(|(index, verb)| PromptRow {
            verb,
            source: "none",
            path: kuzushi_core::relative_prompt_override_path(&module, verb)
                .display()
                .to_string(),
            selected: index == cursor,
        })
        .collect();
    PromptsModel { module, rows }
}

fn focused_module(app: &ShellApp) -> String {
    app.focused_module
        .as_deref()
        .unwrap_or("semgrep")
        .to_string()
}

fn tune_action_rows(app: &ShellApp) -> Vec<TuneActionRow> {
    let cursor = app.tune_cursor_clamped();
    TuneAction::ORDER
        .iter()
        .enumerate()
        .map(|(index, action)| TuneActionRow {
            label: action.label(),
            hint: action.hint(),
            selected: index == cursor,
        })
        .collect()
}

fn house_rules(app: &ShellApp, limit: usize) -> TuneHouseRules {
    match app.read_house_rules_state() {
        HouseRulesRead::Present(text) => {
            TuneHouseRules::Present(text.lines().take(limit).map(ToString::to_string).collect())
        }
        HouseRulesRead::Unreadable(path) => TuneHouseRules::Unreadable(path.display().to_string()),
        _ => TuneHouseRules::Empty,
    }
}

#[cfg(test)]
mod tests;
