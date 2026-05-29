use super::*;
use crate::HistorySearch;

impl ShellApp {
    /// Begin a Ctrl+R reverse-history search seeded with the current input.
    pub(crate) fn enter_history_search(&mut self) {
        self.history_search = Some(HistorySearch {
            query: std::mem::take(&mut self.input),
            cursor: 0,
        });
        self.cursor = 0;
    }

    pub(crate) fn history_search_input(&mut self, ch: char) {
        if let Some(search) = self.history_search.as_mut() {
            search.query.push(ch);
            search.cursor = 0;
        }
    }

    pub(crate) fn history_search_backspace(&mut self) {
        if let Some(search) = self.history_search.as_mut() {
            search.query.pop();
            search.cursor = 0;
        }
    }

    /// Ctrl+R again steps to the next (older) match, wrapping at the end.
    pub(crate) fn history_search_next(&mut self) {
        let len = self.history_search_matches().len();
        if len == 0 {
            return;
        }
        if let Some(search) = self.history_search.as_mut() {
            search.cursor = (search.cursor + 1) % len;
        }
    }

    /// Accept the highlighted match into the prompt and leave search mode.
    pub(crate) fn accept_history_search(&mut self) {
        let chosen = self.current_history_match().map(str::to_string);
        self.history_search = None;
        if let Some(command) = chosen {
            self.input = command;
            self.cursor = self.input.chars().count();
        }
    }

    /// Cancel search, restoring an empty prompt (the pre-search draft was
    /// consumed as the seed query, matching readline's Ctrl+G behavior).
    pub(crate) fn cancel_history_search(&mut self) {
        self.history_search = None;
    }

    /// Indices into `command_history` (most-recent first) that fuzzy-match the
    /// active query.
    pub(crate) fn history_search_matches(&self) -> Vec<usize> {
        let Some(search) = self.history_search.as_ref() else {
            return Vec::new();
        };
        self.command_history
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, command)| subsequence_score(command, &search.query).is_some())
            .map(|(idx, _)| idx)
            .collect()
    }

    pub(crate) fn current_history_match(&self) -> Option<&str> {
        let search = self.history_search.as_ref()?;
        let matches = self.history_search_matches();
        let idx = *matches.get(search.cursor)?;
        self.command_history.get(idx).map(String::as_str)
    }
}
