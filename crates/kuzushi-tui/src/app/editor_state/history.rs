use super::EditorState;
use crate::app::line_editor::subsequence_score;
use crate::app::HistorySearch;
use unicode_segmentation::UnicodeSegmentation;

impl EditorState {
    pub(crate) fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next = match self.history_index {
            None => {
                self.history_draft = self.input.clone();
                self.history_draft_pasted_blocks = self.pasted_blocks.clone();
                self.command_history.len() - 1
            }
            Some(0) => 0,
            Some(idx) => idx - 1,
        };
        self.history_index = Some(next);
        self.input = self.command_history[next].clone();
        self.pasted_blocks.clear();
        self.cursor = self.char_count();
        self.touch_completion_preview();
    }

    pub(crate) fn history_next(&mut self) {
        let Some(idx) = self.history_index else {
            return;
        };
        if idx + 1 < self.command_history.len() {
            self.select_history_entry(idx + 1);
            return;
        }
        self.restore_history_draft();
    }

    pub(crate) fn enter_history_search(&mut self) {
        if self.history_search.is_some() {
            return;
        }
        self.history_search_draft = Some(self.snapshot_input());
        self.history_search = Some(HistorySearch {
            query: std::mem::take(&mut self.input),
            cursor: 0,
        });
        self.pasted_blocks.clear();
        self.cursor = 0;
        self.touch_completion_preview();
    }

    pub(crate) fn history_search_input(&mut self, ch: char) {
        if let Some(search) = self.history_search.as_mut() {
            search.query.push(ch);
            search.cursor = 0;
        }
    }

    pub(crate) fn history_search_backspace(&mut self) {
        if let Some(search) = self.history_search.as_mut() {
            let end = search
                .query
                .grapheme_indices(true)
                .next_back()
                .map_or(0, |(at, _)| at);
            search.query.truncate(end);
            search.cursor = 0;
        }
    }

    pub(crate) fn history_search_next(&mut self) {
        let len = self.history_search_matches().len();
        if len == 0 {
            return;
        }
        if let Some(search) = self.history_search.as_mut() {
            search.cursor = (search.cursor + 1) % len;
        }
    }

    pub(crate) fn accept_history_search(&mut self) {
        let chosen = self.current_history_match().map(str::to_string);
        self.cancel_history_search();
        if let Some(command) = chosen {
            self.input = command;
            self.pasted_blocks.clear();
            self.cursor = self.char_count();
            self.touch_completion_preview();
        }
    }

    pub(crate) fn cancel_history_search(&mut self) {
        self.history_search = None;
        if let Some(draft) = self.history_search_draft.take() {
            self.restore_input_snapshot(draft);
        }
    }

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

    fn select_history_entry(&mut self, index: usize) {
        self.history_index = Some(index);
        self.input = self.command_history[index].clone();
        self.pasted_blocks.clear();
        self.cursor = self.char_count();
        self.touch_completion_preview();
    }

    fn restore_history_draft(&mut self) {
        self.history_index = None;
        self.input = std::mem::take(&mut self.history_draft);
        self.pasted_blocks = std::mem::take(&mut self.history_draft_pasted_blocks);
        self.cursor = self.char_count();
        self.touch_completion_preview();
    }
}

#[cfg(test)]
mod search_draft_tests {
    use super::EditorState;

    #[test]
    fn cancel_and_empty_accept_restore_the_cursor_and_paste_payload() {
        let mut editor = EditorState::default();
        editor.insert_str_at_cursor("draft ");
        editor.insert_multiline_paste("first\nsecond\n");
        editor.set_cursor(2);
        let original = editor.snapshot_input();
        editor.enter_history_search();
        editor.history_search_input('x');
        editor.cancel_history_search();
        assert_eq!(editor.input, original.input);
        assert_eq!(editor.cursor, original.cursor);
        assert_eq!(editor.pasted_blocks, original.pasted_blocks);
        editor.enter_history_search();
        editor.accept_history_search();
        assert_eq!(editor.cursor, 2);
        assert_eq!(editor.expanded_input(), "draft first\nsecond\n");
    }
}
