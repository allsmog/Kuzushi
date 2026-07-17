use super::*;
use std::cell::Ref;

pub(crate) struct CompletionRequest<'a> {
    pub(crate) slash: bool,
    pub(crate) ends_with_space: bool,
    pub(crate) words: Vec<&'a str>,
}

impl<'a> CompletionRequest<'a> {
    pub(crate) fn parse(input: &'a str) -> Self {
        let raw = input.trim_start();
        let slash = raw.starts_with('/');
        let normalized = raw.strip_prefix('/').unwrap_or(raw);
        let ends_with_space = normalized.chars().last().is_some_and(char::is_whitespace);
        let words = normalized.split_whitespace().collect::<Vec<_>>();
        Self {
            slash,
            ends_with_space,
            words,
        }
    }

    pub(crate) fn command_prefix(&self) -> Option<&str> {
        if self.words.is_empty() {
            return Some("");
        }
        (!self.ends_with_space && self.words.len() == 1).then_some(self.words[0])
    }

    pub(crate) fn command(&self) -> &str {
        self.words.first().copied().unwrap_or_default()
    }

    pub(crate) fn current(&self) -> &str {
        if self.ends_with_space {
            ""
        } else {
            self.words.last().copied().unwrap_or_default()
        }
    }

    pub(crate) fn prefix_words(&self) -> &[&str] {
        if self.ends_with_space {
            self.words.as_slice()
        } else {
            &self.words[..self.words.len().saturating_sub(1)]
        }
    }
}

pub(crate) enum CompletionValues<'a> {
    Owned(Vec<String>),
    Static(&'static [&'static str]),
    Borrowed(Ref<'a, [String]>),
    RunIds {
        live: [Option<&'a str>; 3],
        stored: Ref<'a, [String]>,
    },
}

pub(crate) type CompletionValuesFn = for<'a> fn(&'a ShellApp) -> CompletionValues<'a>;

pub(crate) type NestedCompletionFn = fn(&ShellApp, bool, &[&str], &str) -> Vec<String>;

pub(crate) struct PrimaryCompletionProvider {
    pub(crate) commands: &'static [&'static str],
    pub(crate) values: CompletionValuesFn,
}

pub(crate) struct NestedCompletionProvider {
    pub(crate) command: &'static str,
    pub(crate) candidates: NestedCompletionFn,
}

pub(crate) struct SubcommandCompletionRule {
    pub(crate) prefix_words: &'static [&'static str],
    pub(crate) values: CompletionValuesFn,
}

pub(crate) const PRIMARY_COMPLETION_PROVIDERS: &[PrimaryCompletionProvider] = &[
    PrimaryCompletionProvider {
        commands: &["use"],
        values: module_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["run", "options"],
        values: tool_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["set", "setg", "unset", "unsetg"],
        values: option_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["kb"],
        values: attachment_module_completion_values,
    },
    PrimaryCompletionProvider {
        commands: &["attach"],
        values: file_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["detach", "reparse"],
        values: attachment_id_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["open"],
        values: finding_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["replay", "trace", "resume"],
        values: run_id_completion_values_for,
    },
    PrimaryCompletionProvider {
        commands: &["config"],
        values: config_completion_values,
    },
    PrimaryCompletionProvider {
        commands: &["model"],
        values: model_completion_values,
    },
];
