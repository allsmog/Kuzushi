use std::collections::BTreeSet;
use std::fs;

use kuzushi_core::{
    sorted_finding_aliases, FindingStore, WorkspaceTarget, SUPPORTED_ATTACHMENT_MODULES,
};

use crate::commands::shell_command_specs;

use super::findings::short_fingerprint;
use super::sast_tasks::valid_sast_task_ids;
use super::{model_choices, CompletionCycle, ShellApp};

fn char_index_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

impl ShellApp {
    pub fn set_input(&mut self, value: impl Into<String>) {
        self.input = value.into();
        self.cursor = self.input.chars().count();
        self.history_index = None;
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.history_index = None;
    }

    /// Esc behavior: clear an in-progress draft, stash it for one-shot undo.
    /// If the draft is already empty, restore the most recently cleared
    /// draft so a single mis-tapped Esc doesn't lose carefully-typed input.
    pub fn esc_clear_or_restore(&mut self) {
        if !self.input.is_empty() {
            self.last_cleared_input = Some(std::mem::take(&mut self.input));
            self.cursor = 0;
            self.history_index = None;
            return;
        }
        if let Some(stashed) = self.last_cleared_input.take() {
            self.input = stashed;
            self.cursor = self.char_count();
            self.history_index = None;
        }
    }

    pub fn take_input(&mut self) -> String {
        self.cursor = 0;
        self.history_index = None;
        std::mem::take(&mut self.input)
    }

    fn char_count(&self) -> usize {
        self.input.chars().count()
    }

    fn cursor_byte(&self) -> usize {
        char_index_to_byte(&self.input, self.cursor)
    }

    pub fn insert_str_at_cursor(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let byte = self.cursor_byte();
        self.input.insert_str(byte, s);
        self.cursor += s.chars().count();
        self.history_index = None;
    }

    pub fn insert_char_at_cursor(&mut self, ch: char) {
        let byte = self.cursor_byte();
        self.input.insert(byte, ch);
        self.cursor += 1;
        self.history_index = None;
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let count = self.char_count();
        if self.cursor > count {
            self.cursor = count;
        }
        let new_cursor = self.cursor - 1;
        let start = char_index_to_byte(&self.input, new_cursor);
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(start..end);
        self.cursor = new_cursor;
        self.history_index = None;
    }

    pub fn delete_forward(&mut self) {
        let count = self.char_count();
        if self.cursor >= count {
            return;
        }
        let start = char_index_to_byte(&self.input, self.cursor);
        let end = char_index_to_byte(&self.input, self.cursor + 1);
        self.input.drain(start..end);
        self.history_index = None;
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        let count = self.char_count();
        if self.cursor < count {
            self.cursor += 1;
        }
    }

    pub fn move_cursor_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_cursor_end(&mut self) {
        self.cursor = self.char_count();
    }

    fn word_boundary_left(&self) -> usize {
        // "Word" = run of alphanumeric chars (incl. underscore). Treat punctuation and
        // whitespace as separators so Ctrl+W on "./path/to/foo" stops at each '/'. Skip
        // separators directly before the cursor first, then the run of word chars.
        let chars: Vec<char> = self.input.chars().collect();
        let mut idx = self.cursor.min(chars.len());
        while idx > 0 && !is_word_char(chars[idx - 1]) {
            idx -= 1;
        }
        while idx > 0 && is_word_char(chars[idx - 1]) {
            idx -= 1;
        }
        idx
    }

    fn word_boundary_right(&self) -> usize {
        let chars: Vec<char> = self.input.chars().collect();
        let mut idx = self.cursor.min(chars.len());
        let len = chars.len();
        while idx < len && is_word_char(chars[idx]) {
            idx += 1;
        }
        while idx < len && !is_word_char(chars[idx]) {
            idx += 1;
        }
        idx
    }

    pub fn delete_word_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let target = self.word_boundary_left();
        let start = char_index_to_byte(&self.input, target);
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(start..end);
        self.cursor = target;
        self.history_index = None;
    }

    pub fn move_cursor_word_left(&mut self) {
        self.cursor = self.word_boundary_left();
    }

    pub fn move_cursor_word_right(&mut self) {
        self.cursor = self.word_boundary_right();
    }

    pub fn kill_to_start(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let end = char_index_to_byte(&self.input, self.cursor);
        self.input.drain(..end);
        self.cursor = 0;
        self.history_index = None;
    }

    pub fn kill_to_end(&mut self) {
        let start = char_index_to_byte(&self.input, self.cursor);
        self.input.truncate(start);
        self.history_index = None;
    }

    pub fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next = match self.history_index {
            None => {
                self.history_draft = self.input.clone();
                self.command_history.len() - 1
            }
            Some(0) => 0,
            Some(idx) => idx - 1,
        };
        self.history_index = Some(next);
        self.input = self.command_history[next].clone();
        self.cursor = self.char_count();
    }

    pub fn history_next(&mut self) {
        let Some(idx) = self.history_index else {
            return;
        };
        if idx + 1 < self.command_history.len() {
            let next = idx + 1;
            self.history_index = Some(next);
            self.input = self.command_history[next].clone();
            self.cursor = self.char_count();
        } else {
            self.history_index = None;
            self.input = std::mem::take(&mut self.history_draft);
            self.cursor = self.char_count();
        }
    }

    pub fn completion_candidates(&self, input: &str) -> Vec<String> {
        let raw = input.trim_start();
        let slash = raw.starts_with('/');
        let normalized = raw.strip_prefix('/').unwrap_or(raw);
        let ends_with_space = normalized.chars().last().is_some_and(char::is_whitespace);
        let words = normalized.split_whitespace().collect::<Vec<_>>();

        if words.is_empty() {
            return command_completion_candidates("", slash);
        }
        if words.len() == 1 && !ends_with_space {
            return command_completion_candidates(words[0], slash);
        }

        let current = if ends_with_space {
            ""
        } else {
            words.last().copied().unwrap_or_default()
        };
        let prefix_words = if ends_with_space {
            words.as_slice()
        } else {
            &words[..words.len().saturating_sub(1)]
        };

        match words.first().copied().unwrap_or_default() {
            "use" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.module_completion_values(),
            ),
            "run" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            "options" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            "set" | "setg" | "unset" | "unsetg" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.option_completion_values(),
            ),
            "task" => self.task_completion_candidates(slash, prefix_words, current),
            "context" => self.context_completion_candidates(slash, prefix_words, current),
            "workspace" => self.workspace_completion_candidates(slash, prefix_words, current),
            "kb" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                SUPPORTED_ATTACHMENT_MODULES
                    .iter()
                    .map(|module| (*module).to_string())
                    .collect(),
            ),
            "detach" | "reparse" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.attachment_id_completion_values(),
            ),
            "open" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.finding_completion_values(),
            ),
            "replay" | "trace" | "resume" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.run_id_completion_values(),
            ),
            "config" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                config_completion_keys()
                    .iter()
                    .map(|key| (*key).to_string())
                    .collect(),
            ),
            "model" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                model_choices()
                    .iter()
                    .flat_map(|choice| [choice.index.to_string(), choice.id.to_string()])
                    .collect(),
            ),
            "auth" => self.auth_completion_candidates(slash, prefix_words, current),
            "show" => self.show_completion_candidates(slash, prefix_words, current),
            _ => Vec::new(),
        }
    }

    pub(super) fn apply_completion(&mut self) {
        // First Tab: snapshot the operator's prefix and produce the candidate
        // list. Subsequent Tabs advance through the list without recomputing,
        // so cycling stays stable even after we've replaced `input` with a
        // longer candidate that would otherwise filter the candidates down.
        let active_cycle = self.completion_cycle.take();
        let cycle = match active_cycle {
            Some(cycle)
                if !cycle.candidates.is_empty()
                    && self
                        .input
                        .as_str()
                        .eq(cycle.candidates[cycle.index].as_str()) =>
            {
                cycle
            }
            _ => {
                let candidates = self.completion_candidates(&self.input);
                if candidates.is_empty() {
                    return;
                }
                CompletionCycle {
                    prefix: self.input.clone(),
                    candidates,
                    index: usize::MAX, // pre-increment in next step lands on 0
                }
            }
        };
        let next_index = if cycle.index == usize::MAX {
            0
        } else {
            (cycle.index + 1) % cycle.candidates.len()
        };
        let candidate = cycle.candidates[next_index].clone();
        self.set_input(candidate);
        self.completion_cycle = Some(CompletionCycle {
            prefix: cycle.prefix,
            candidates: cycle.candidates,
            index: next_index,
        });
    }

    pub(crate) fn reset_completion_cycle(&mut self) {
        self.completion_cycle = None;
    }

    /// Inline ghost-text suggestion shown after the cursor when the cursor sits
    /// at the end of the line. Returns the *tail* — the chars the operator would
    /// gain by pressing Tab — or `None` if there is no completion or the cursor
    /// is mid-line. Empty inputs return `None` so the cold-start prompt isn't
    /// noisy.
    pub fn completion_preview(&self) -> Option<String> {
        if self.input.is_empty() {
            return None;
        }
        if self.cursor != self.input.chars().count() {
            return None;
        }
        let candidate = self.completion_candidates(&self.input).into_iter().next()?;
        if candidate == self.input {
            return None;
        }
        candidate
            .strip_prefix(&self.input)
            .filter(|tail| !tail.is_empty())
            .map(str::to_string)
    }

    fn module_completion_values(&self) -> Vec<String> {
        self.registry
            .modules()
            .map(|module| module.metadata().id.clone())
            .collect()
    }

    fn tool_completion_values(&self) -> Vec<String> {
        let mut values = self
            .registry
            .tools()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        if let Some(module) = self.focused_module.as_ref() {
            let prefix = format!("{module}:");
            values.extend(self.registry.tools().filter_map(|tool| {
                tool.name
                    .strip_prefix(&prefix)
                    .map(|short_name| short_name.to_string())
            }));
        }
        values
    }

    fn option_completion_values(&self) -> Vec<String> {
        self.resolve_options_tool(None)
            .ok()
            .and_then(|tool_name| self.registry.resolve_tool(&tool_name))
            .map(|tool| tool.options.iter().map(|spec| spec.name.clone()).collect())
            .unwrap_or_default()
    }

    fn task_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["task"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["block", "allow", "toggle", "mode", "reset"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["task", "mode"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["auto", "manual", "toggle"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["task", "block" | "allow" | "toggle" | "deny" | "unblock"] => {
                complete_value_candidates(
                    slash,
                    prefix_words,
                    current,
                    valid_sast_task_ids()
                        .iter()
                        .map(|id| (*id).to_string())
                        .collect(),
                )
            }
            _ => Vec::new(),
        }
    }

    fn context_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["context"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["build", "status", "regen"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["context", "regen"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["all", "repo", "app-model"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn workspace_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["workspace"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["status", "export"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["workspace", "export"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["findings"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn auth_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["auth"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["status", "login", "codex", "anthropic"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["auth", "login"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["openai-codex", "anthropic"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn show_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["show"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                [
                    "modules", "tools", "options", "advanced", "missing", "aliases", "runs",
                    "prompts",
                ]
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ),
            ["show", "options"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            ["show", "aliases"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.finding_completion_values(),
            ),
            _ => Vec::new(),
        }
    }

    fn attachment_id_completion_values(&self) -> Vec<String> {
        self.kb_view
            .attachments
            .iter()
            .map(|record| record.id.clone())
            .collect()
    }

    fn finding_completion_values(&self) -> Vec<String> {
        let mut findings = self.findings.clone();
        if findings.is_empty() {
            if let Some(target) = self.target.as_ref() {
                if let Ok(workspace) = WorkspaceTarget::new(target) {
                    if let Ok(store) = FindingStore::open(workspace.findings_db_path()) {
                        if let Ok(stored) = store.list_findings(200) {
                            findings = stored;
                        }
                    }
                }
            }
        }

        let mut values = Vec::new();
        for (alias, finding) in sorted_finding_aliases(&findings) {
            values.push(alias);
            values.push(short_fingerprint(&finding.fingerprint));
            values.push(finding.fingerprint.clone());
        }
        values
    }

    fn run_id_completion_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(run_id) = self.scan.as_ref().and_then(|scan| scan.run_id.clone()) {
            values.push(run_id);
        }
        if let Some(target) = self.target.as_ref() {
            let runs_dir = target.join(".kuzushi/runs");
            if let Ok(entries) = fs::read_dir(runs_dir) {
                values.extend(entries.flatten().filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(|file_type| file_type.is_dir())
                        .and_then(|_| entry.file_name().into_string().ok())
                }));
            }
        }
        values
    }
}

fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        for form in std::iter::once(spec.command).chain(spec.aliases.iter().copied()) {
            let Some(head) = command_completion_head(form) else {
                continue;
            };
            if slash && head.starts_with('?') {
                continue;
            }
            let candidate = if slash && !head.starts_with('/') {
                format!("/{head}")
            } else {
                head
            };
            let comparable = candidate.strip_prefix('/').unwrap_or(&candidate);
            if comparable.starts_with(prefix) || candidate.starts_with(prefix) {
                values.push(candidate);
            }
        }
    }
    dedupe_sorted(values)
}

fn command_completion_head(template: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in template.split_whitespace() {
        if part.contains('<') || part.contains('[') || part.contains('|') {
            break;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn complete_value_candidates(
    slash: bool,
    prefix_words: &[&str],
    current: &str,
    values: Vec<String>,
) -> Vec<String> {
    let current_lower = current.to_ascii_lowercase();
    let head = prefix_words.join(" ");
    let slash_prefix = if slash { "/" } else { "" };
    let candidates = values
        .into_iter()
        .filter(|value| {
            current_lower.is_empty() || value.to_ascii_lowercase().starts_with(&current_lower)
        })
        .map(|value| {
            if head.is_empty() {
                format!("{slash_prefix}{value}")
            } else {
                format!("{slash_prefix}{head} {value}")
            }
        })
        .collect();
    dedupe_sorted(candidates)
}

fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn config_completion_keys() -> &'static [&'static str] {
    &[
        "model",
        "runtime.kind",
        "runtime.api_key_env",
        "runtime.agent_bridge_command",
        "target",
        "workspace",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn word_boundary_right_skips_current_word_then_separator() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.input = "./path/to foo".to_string();
        app.cursor = 0;

        app.move_cursor_word_right();
        assert_eq!(app.cursor, 2);
        app.move_cursor_word_right();
        assert_eq!(app.cursor, 7);
        app.move_cursor_word_right();
        assert_eq!(app.cursor, 10);
    }

    #[test]
    fn show_completion_candidates_cover_show_subcommands() {
        let app = ShellApp::new(V2Config::default(), None);

        let aliases = app.completion_candidates("show a");
        assert!(aliases.contains(&"show aliases".to_string()));

        let all = app.completion_candidates("/show ");
        assert!(all.contains(&"/show modules".to_string()));
        assert!(all.contains(&"/show prompts".to_string()));
    }
}
