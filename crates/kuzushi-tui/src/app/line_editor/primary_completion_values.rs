use super::*;

pub(crate) const NESTED_COMPLETION_PROVIDERS: &[NestedCompletionProvider] = &[
    NestedCompletionProvider {
        command: "set",
        candidates: ShellApp::option_setting_completion_candidates,
    },
    NestedCompletionProvider {
        command: "setg",
        candidates: ShellApp::option_setting_completion_candidates,
    },
    NestedCompletionProvider {
        command: "task",
        candidates: ShellApp::task_completion_candidates,
    },
    NestedCompletionProvider {
        command: "context",
        candidates: ShellApp::context_completion_candidates,
    },
    NestedCompletionProvider {
        command: "workspace",
        candidates: ShellApp::workspace_completion_candidates,
    },
    NestedCompletionProvider {
        command: "auth",
        candidates: ShellApp::auth_completion_candidates,
    },
    NestedCompletionProvider {
        command: "show",
        candidates: ShellApp::show_completion_candidates,
    },
    NestedCompletionProvider {
        command: "threats",
        candidates: ShellApp::threats_completion_candidates,
    },
    NestedCompletionProvider {
        command: "prompt",
        candidates: ShellApp::prompt_completion_candidates,
    },
];

pub(crate) const TASK_COMPLETION_RULES: &[SubcommandCompletionRule] = &[
    SubcommandCompletionRule {
        prefix_words: &["task"],
        values: task_action_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "mode"],
        values: task_mode_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "block"],
        values: sast_task_id_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "allow"],
        values: sast_task_id_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "toggle"],
        values: sast_task_id_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "deny"],
        values: sast_task_id_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["task", "unblock"],
        values: sast_task_id_completion_values,
    },
];

pub(crate) const CONTEXT_COMPLETION_RULES: &[SubcommandCompletionRule] = &[
    SubcommandCompletionRule {
        prefix_words: &["context"],
        values: context_action_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["context", "regen"],
        values: context_regen_completion_values,
    },
];

pub(crate) const WORKSPACE_COMPLETION_RULES: &[SubcommandCompletionRule] = &[
    SubcommandCompletionRule {
        prefix_words: &["workspace"],
        values: workspace_action_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["workspace", "export"],
        values: workspace_export_completion_values,
    },
];

pub(crate) const AUTH_COMPLETION_RULES: &[SubcommandCompletionRule] = &[
    SubcommandCompletionRule {
        prefix_words: &["auth"],
        values: auth_action_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["auth", "login"],
        values: auth_login_completion_values,
    },
];

pub(crate) const THREATS_COMPLETION_RULES: &[SubcommandCompletionRule] =
    &[SubcommandCompletionRule {
        prefix_words: &["threats"],
        values: threats_action_completion_values,
    }];

pub(crate) const PROMPT_COMPLETION_RULES: &[SubcommandCompletionRule] =
    &[SubcommandCompletionRule {
        prefix_words: &["prompt"],
        values: prompt_action_completion_values,
    }];

pub(crate) const SHOW_COMPLETION_RULES: &[SubcommandCompletionRule] = &[
    SubcommandCompletionRule {
        prefix_words: &["show"],
        values: show_action_completion_values,
    },
    SubcommandCompletionRule {
        prefix_words: &["show", "options"],
        values: tool_completion_values_for,
    },
    SubcommandCompletionRule {
        prefix_words: &["show", "advanced"],
        values: tool_completion_values_for,
    },
    SubcommandCompletionRule {
        prefix_words: &["show", "missing"],
        values: tool_completion_values_for,
    },
    SubcommandCompletionRule {
        prefix_words: &["show", "aliases"],
        values: finding_completion_values_for,
    },
];

pub(crate) fn primary_completion_values<'a>(
    app: &'a ShellApp,
    command: &str,
) -> Option<CompletionValues<'a>> {
    PRIMARY_COMPLETION_PROVIDERS
        .iter()
        .find(|provider| provider.commands.contains(&command))
        .map(|provider| (provider.values)(app))
}
