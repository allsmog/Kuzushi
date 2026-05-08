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

pub(crate) fn module_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.module_completion_values()
}

pub(crate) fn tool_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.tool_completion_values()
}

pub(crate) fn option_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.option_completion_values()
}

pub(crate) fn attachment_id_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.attachment_id_completion_values()
}

pub(crate) fn finding_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.finding_completion_values()
}

pub(crate) fn run_id_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.run_id_completion_values()
}

pub(crate) fn attachment_module_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(SUPPORTED_ATTACHMENT_MODULES)
}

pub(crate) fn config_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(config_completion_keys())
}

pub(crate) fn model_completion_values(_: &ShellApp) -> Vec<String> {
    model_choices()
        .iter()
        .flat_map(|choice| [choice.index.to_string(), choice.id.to_string()])
        .collect()
}

pub(crate) fn task_action_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["block", "allow", "toggle", "mode", "reset"])
}

pub(crate) fn task_mode_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["auto", "manual", "toggle"])
}

pub(crate) fn sast_task_id_completion_values(_: &ShellApp) -> Vec<String> {
    valid_sast_task_ids()
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub(crate) fn context_action_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["build", "status", "regen"])
}

pub(crate) fn context_regen_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["all", "repo", "app-model"])
}

pub(crate) fn workspace_action_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["status", "export"])
}

pub(crate) fn workspace_export_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["findings"])
}

pub(crate) fn auth_action_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["status", "login", "codex", "anthropic"])
}

pub(crate) fn auth_login_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&["openai-codex", "anthropic"])
}

pub(crate) fn show_action_completion_values(_: &ShellApp) -> Vec<String> {
    string_values(&[
        "modules", "tools", "options", "advanced", "missing", "aliases", "runs", "prompts",
    ])
}

pub(crate) fn string_values(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
