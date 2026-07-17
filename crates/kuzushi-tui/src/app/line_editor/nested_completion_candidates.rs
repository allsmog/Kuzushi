use super::*;

pub(crate) fn nested_completion_candidates(
    app: &ShellApp,
    command: &str,
    slash: bool,
    prefix_words: &[&str],
    current: &str,
) -> Option<Vec<String>> {
    NESTED_COMPLETION_PROVIDERS
        .iter()
        .find(|provider| provider.command == command)
        .map(|provider| (provider.candidates)(app, slash, prefix_words, current))
}

pub(crate) fn complete_subcommand_rules(
    app: &ShellApp,
    rules: &[SubcommandCompletionRule],
    slash: bool,
    prefix_words: &[&str],
    current: &str,
) -> Vec<String> {
    rules
        .iter()
        .find(|rule| rule.prefix_words == prefix_words)
        .map(|rule| complete_value_candidates(slash, prefix_words, current, (rule.values)(app)))
        .unwrap_or_default()
}

pub(crate) fn module_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(app.module_completion_values())
}

pub(crate) fn tool_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(app.tool_completion_values())
}

pub(crate) fn option_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(app.option_completion_values())
}

pub(crate) fn attachment_id_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(app.attachment_id_completion_values())
}

pub(crate) fn finding_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    app.finding_completion_values()
}

pub(crate) fn run_id_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    app.run_id_completion_values()
}

pub(crate) fn attachment_module_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(SUPPORTED_ATTACHMENT_MODULES)
}

pub(crate) fn config_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(config_completion_keys())
}

pub(crate) fn model_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(
        model_choices()
            .iter()
            .flat_map(|choice| {
                [
                    choice.index.to_string(),
                    crate::app::model_choice_display_selector(choice),
                ]
            })
            .collect(),
    )
}

/// Canonical sub-verb list for a group verb. Single source of truth shared by
/// Tab-completion and the `<verb> ?` inline lister so they never drift.
pub(crate) fn subverb_listing(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "task" => &["block", "allow", "toggle", "mode", "reset"],
        "context" => &["build", "status", "regen"],
        "workspace" => &["status", "export"],
        "auth" => &["status", "login", "openai", "anthropic", "github-copilot"],
        "show" => &[
            "modules", "tools", "options", "advanced", "missing", "aliases", "runs", "prompts",
        ],
        "threats" => &[
            "summary", "dfd", "stride", "stories", "scope", "edit", "regen", "apply", "reject",
            "ask",
        ],
        "prompt" => &["edit", "show", "diff", "reset"],
        _ => return None,
    })
}

fn subverb_values(verb: &str) -> CompletionValues<'static> {
    CompletionValues::Static(subverb_listing(verb).unwrap_or(&[]))
}

pub(crate) fn task_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("task")
}

pub(crate) fn threats_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("threats")
}

pub(crate) fn prompt_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("prompt")
}

pub(crate) fn task_mode_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(&["auto", "manual", "toggle"])
}

pub(crate) fn sast_task_id_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Owned(
        valid_sast_task_ids()
            .into_iter()
            .map(str::to_string)
            .collect(),
    )
}

pub(crate) fn context_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("context")
}

pub(crate) fn context_regen_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(&["all", "repo", "app-model"])
}

pub(crate) fn workspace_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("workspace")
}

pub(crate) fn workspace_export_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(&["findings"])
}

pub(crate) fn auth_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("auth")
}

pub(crate) fn auth_login_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    CompletionValues::Static(&[
        "openai",
        "openai browser",
        "openai headless",
        "anthropic",
        "github-copilot",
    ])
}

pub(crate) fn show_action_completion_values(_: &ShellApp) -> CompletionValues<'_> {
    subverb_values("show")
}
