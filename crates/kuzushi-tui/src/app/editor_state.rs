use super::*;
use std::cell::{Ref, RefCell};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
mod grapheme_tests;
mod graphemes;
mod history;
mod paste;
#[cfg(test)]
mod paste_tests;
pub(crate) use paste::PasteInspection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EditorClearResult {
    Ignored,
    CompletionRestored,
    DraftCleared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompletionPreviewKey {
    pub(crate) editor_revision: u64,
    pub(crate) cursor: usize,
    pub(crate) input_mode: InputMode,
    pub(crate) cache_generation: u64,
    pub(crate) command_provider_generation: u64,
}

#[derive(Debug, Clone)]
struct CompletionPreviewMemo {
    key: CompletionPreviewKey,
    target: Option<PathBuf>,
    preview: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PastedBlock {
    marker: String,
    text: Arc<str>,
    range: Range<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct EditorInputSnapshot {
    input: String,
    cursor: usize,
    pasted_blocks: Vec<PastedBlock>,
}

#[derive(Debug, Clone)]
pub(crate) struct EditorState {
    input: String,
    cursor: usize,
    command_history: Vec<String>,
    history_index: Option<usize>,
    history_draft: String,
    history_draft_pasted_blocks: Vec<PastedBlock>,
    last_cleared_input: Option<String>,
    last_cleared_pasted_blocks: Vec<PastedBlock>,
    pasted_blocks: Vec<PastedBlock>,
    next_paste_id: u64,
    paste_undo: Vec<EditorInputSnapshot>,
    paste_inspection: Option<PasteInspection>,
    completion_cycle: Option<CompletionCycle>,
    input_mode: InputMode,
    /// Result-card key that just resolved a RESULT READY card. A repeat of
    /// that exact key (a stale-frame re-press) is absorbed instead of typed.
    resolved_result_key: Option<char>,
    history_search: Option<HistorySearch>,
    history_search_draft: Option<EditorInputSnapshot>,
    revision: u64,
    completion_preview: RefCell<Option<CompletionPreviewMemo>>,
    #[cfg(test)]
    completion_preview_recomputations: std::cell::Cell<usize>,
}

impl Default for EditorState {
    fn default() -> Self {
        Self {
            input: String::new(),
            cursor: 0,
            command_history: Vec::new(),
            history_index: None,
            history_draft: String::new(),
            history_draft_pasted_blocks: Vec::new(),
            last_cleared_input: None,
            last_cleared_pasted_blocks: Vec::new(),
            pasted_blocks: Vec::new(),
            next_paste_id: 0,
            paste_undo: Vec::new(),
            paste_inspection: None,
            completion_cycle: None,
            input_mode: InputMode::Prompt,
            resolved_result_key: None,
            history_search: None,
            history_search_draft: None,
            revision: 0,
            completion_preview: RefCell::new(None),
            #[cfg(test)]
            completion_preview_recomputations: std::cell::Cell::new(0),
        }
    }
}

impl EditorState {
    pub(crate) fn input(&self) -> &str {
        &self.input
    }

    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    pub(crate) fn command_history(&self) -> &[String] {
        &self.command_history
    }

    pub(crate) fn replace_command_history(&mut self, history: Vec<String>) {
        self.command_history = history;
        self.history_index = None;
    }

    pub(crate) fn push_command_history(&mut self, command: impl Into<String>, cap: usize) {
        self.command_history.push(command.into());
        if self.command_history.len() > cap {
            let overflow = self.command_history.len() - cap;
            self.command_history.drain(0..overflow);
        }
        self.history_index = None;
    }

    pub(crate) fn set_cursor(&mut self, cursor: usize) {
        let cursor = self.atomic_floor(graphemes::floor(&self.input, cursor));
        if self.cursor != cursor {
            self.cursor = cursor;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn input_mode(&self) -> InputMode {
        self.input_mode
    }

    pub(crate) fn set_input_mode(&mut self, mode: InputMode) {
        if self.input_mode != mode {
            self.input_mode = mode;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn resolved_result_key(&self) -> Option<char> {
        self.resolved_result_key
    }

    pub(crate) fn set_resolved_result_key(&mut self, key: Option<char>) {
        self.resolved_result_key = key;
    }

    pub(crate) fn history_search(&self) -> Option<&HistorySearch> {
        self.history_search.as_ref()
    }

    pub(crate) fn completion_cycle(&self) -> Option<&CompletionCycle> {
        self.completion_cycle.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn last_cleared_input(&self) -> Option<&str> {
        self.last_cleared_input.as_deref()
    }

    pub(crate) fn set_last_cleared_input(&mut self, input: Option<String>) {
        self.last_cleared_input = input;
        self.last_cleared_pasted_blocks.clear();
    }

    pub(crate) fn set_input(&mut self, value: impl Into<String>) {
        let value = value.into();
        let cursor = value.chars().count();
        if self.input == value && self.cursor == cursor {
            return;
        }
        if self.input != value {
            self.remember_paste_edit();
            self.pasted_blocks.clear();
        }
        self.input = value;
        self.cursor = cursor;
        self.history_index = None;
        self.touch_completion_preview();
    }

    pub(crate) fn clear_input(&mut self) {
        if self.input.is_empty() && self.paste_undo.is_empty() {
            return;
        }
        self.input.clear();
        self.pasted_blocks.clear();
        self.paste_undo.clear();
        self.paste_inspection = None;
        self.cursor = 0;
        self.history_index = None;
        self.touch_completion_preview();
    }

    pub(crate) fn take_input(&mut self) -> String {
        self.paste_undo.clear();
        self.paste_inspection = None;
        let changed = !self.input.is_empty() || self.cursor != 0 || !self.pasted_blocks.is_empty();
        self.cursor = 0;
        self.history_index = None;
        let input = std::mem::take(&mut self.input);
        let pasted_blocks = std::mem::take(&mut self.pasted_blocks);
        if changed {
            self.touch_completion_preview();
        }
        expand_pasted_blocks(input, &pasted_blocks)
    }

    pub(crate) fn expanded_input(&self) -> String {
        expand_pasted_blocks(self.input.clone(), &self.pasted_blocks)
    }

    pub(crate) fn snapshot_input(&self) -> EditorInputSnapshot {
        EditorInputSnapshot {
            input: self.input.clone(),
            cursor: self.cursor,
            pasted_blocks: self.pasted_blocks.clone(),
        }
    }

    pub(crate) fn restore_input_snapshot(&mut self, snapshot: EditorInputSnapshot) {
        let cursor = graphemes::floor(&snapshot.input, snapshot.cursor);
        if self.input == snapshot.input
            && self.cursor == cursor
            && self.pasted_blocks == snapshot.pasted_blocks
        {
            return;
        }
        self.input = snapshot.input;
        self.cursor = cursor;
        self.pasted_blocks = snapshot.pasted_blocks;
        self.history_index = None;
        self.touch_completion_preview();
    }

    pub(crate) fn esc_clear_input_or_completion(&mut self) -> EditorClearResult {
        if self.restore_completion_prefix() {
            return EditorClearResult::CompletionRestored;
        }
        if self.stash_and_clear_input() {
            return EditorClearResult::DraftCleared;
        }
        EditorClearResult::Ignored
    }

    pub(crate) fn stash_and_clear_input(&mut self) -> bool {
        if self.input.is_empty() {
            return false;
        }
        self.last_cleared_input = Some(std::mem::take(&mut self.input));
        self.last_cleared_pasted_blocks = std::mem::take(&mut self.pasted_blocks);
        self.cursor = 0;
        self.history_index = None;
        self.touch_completion_preview();
        true
    }

    pub(crate) fn restore_last_cleared_input(&mut self) -> bool {
        if let Some(stashed) = self.last_cleared_input.take() {
            self.input = stashed;
            self.pasted_blocks = std::mem::take(&mut self.last_cleared_pasted_blocks);
            self.cursor = self.char_count();
            self.history_index = None;
            self.touch_completion_preview();
            true
        } else if let Some(snapshot) = self.paste_undo.pop() {
            self.restore_input_snapshot(snapshot);
            true
        } else {
            false
        }
    }

    pub(crate) fn take_completion_cycle(&mut self) -> Option<CompletionCycle> {
        self.completion_cycle.take()
    }

    pub(crate) fn set_completion_cycle(&mut self, cycle: CompletionCycle) {
        self.completion_cycle = Some(cycle);
    }

    pub(crate) fn reset_completion_cycle(&mut self) {
        self.completion_cycle = None;
    }

    pub(crate) fn char_count(&self) -> usize {
        self.input.chars().count()
    }

    pub(crate) fn insert_str_at_cursor(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        self.replace_edit(self.cursor..self.cursor, s);
    }

    pub(crate) fn insert_multiline_paste(&mut self, text: &str) -> String {
        self.reset_completion_cycle();
        self.push_paste_undo();
        self.next_paste_id = self.next_paste_id.wrapping_add(1).max(1);
        let lines = text.split('\n').count();
        let chars = text.chars().count();
        let marker = format!(
            "⟪paste #{} · {lines} lines · {chars} chars⟫",
            self.next_paste_id
        );
        let start = self.cursor;
        self.insert_str_at_cursor(&marker);
        self.pasted_blocks.push(PastedBlock {
            marker: marker.clone(),
            text: Arc::from(text),
            range: start..self.cursor,
        });
        marker
    }

    pub(crate) fn insert_char_at_cursor(&mut self, ch: char) {
        self.insert_str_at_cursor(ch.encode_utf8(&mut [0; 4]));
    }

    pub(crate) fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = graphemes::previous(&self.input, self.cursor);
        self.replace_edit(start..self.cursor, "");
    }

    pub(crate) fn delete_forward(&mut self) {
        let count = self.char_count();
        if self.cursor >= count {
            return;
        }
        let end = graphemes::next(&self.input, self.cursor);
        self.replace_edit(self.cursor..end, "");
    }

    pub(crate) fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.atomic_floor(graphemes::previous(&self.input, self.cursor));
            self.touch_completion_preview();
        }
    }

    pub(crate) fn move_cursor_right(&mut self) {
        let count = self.char_count();
        if self.cursor < count {
            self.cursor = self.atomic_ceil(graphemes::next(&self.input, self.cursor));
            self.touch_completion_preview();
        }
    }

    pub(crate) fn move_cursor_home(&mut self) {
        if self.cursor != 0 {
            self.cursor = 0;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn move_cursor_end(&mut self) {
        let end = self.char_count();
        if self.cursor != end {
            self.cursor = end;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn word_boundary_left(&self) -> usize {
        self.atomic_floor(graphemes::word_left(&self.input, self.cursor))
    }

    pub(crate) fn word_boundary_right(&self) -> usize {
        self.atomic_ceil(graphemes::word_right(&self.input, self.cursor))
    }

    pub(crate) fn delete_word_left(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let target = self.word_boundary_left();
        self.replace_edit(target..self.cursor, "");
    }

    pub(crate) fn move_cursor_word_left(&mut self) {
        let target = self.word_boundary_left();
        if self.cursor != target {
            self.cursor = target;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn move_cursor_word_right(&mut self) {
        let target = self.word_boundary_right();
        if self.cursor != target {
            self.cursor = target;
            self.touch_completion_preview();
        }
    }

    pub(crate) fn kill_to_start(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.replace_edit(0..self.cursor, "");
    }

    pub(crate) fn kill_to_end(&mut self) {
        let start = char_index_to_byte(&self.input, self.cursor);
        if start == self.input.len() {
            return;
        }
        self.replace_edit(self.cursor..self.char_count(), "");
    }

    fn restore_completion_prefix(&mut self) -> bool {
        let Some(cycle) = self.completion_cycle.take() else {
            return false;
        };
        if cycle.prefix.is_empty() && self.input.is_empty() {
            return true;
        }
        self.input = cycle.prefix;
        self.pasted_blocks.clear();
        self.paste_inspection = None;
        self.cursor = self.char_count();
        self.history_index = None;
        self.touch_completion_preview();
        true
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn completion_preview_matches(
        &self,
        key: CompletionPreviewKey,
        target: Option<&Path>,
    ) -> bool {
        self.completion_preview
            .borrow()
            .as_ref()
            .is_some_and(|memo| memo.key == key && memo.target.as_deref() == target)
    }

    pub(crate) fn store_completion_preview(
        &self,
        key: CompletionPreviewKey,
        target: Option<&Path>,
        preview: Option<String>,
    ) {
        *self.completion_preview.borrow_mut() = Some(CompletionPreviewMemo {
            key,
            target: target.map(Path::to_path_buf),
            preview,
        });
        #[cfg(test)]
        self.completion_preview_recomputations
            .set(self.completion_preview_recomputations.get() + 1);
    }

    pub(crate) fn completion_preview(&self) -> Option<Ref<'_, str>> {
        Ref::filter_map(self.completion_preview.borrow(), |memo| {
            memo.as_ref()?.preview.as_deref()
        })
        .ok()
    }

    pub(crate) fn invalidate_completion_preview(&mut self) {
        self.completion_preview.get_mut().take();
    }

    #[cfg(test)]
    pub(crate) fn completion_preview_recomputations(&self) -> usize {
        self.completion_preview_recomputations.get()
    }

    fn touch_completion_preview(&mut self) {
        self.cursor = self.atomic_floor(graphemes::floor(&self.input, self.cursor));
        self.revision = self.revision.wrapping_add(1);
        self.invalidate_completion_preview();
    }
}

fn expand_pasted_blocks(input: String, blocks: &[PastedBlock]) -> String {
    let mut occurrences = blocks
        .iter()
        .map(|block| (char_index_to_byte(&input, block.range.start), block))
        .collect::<Vec<_>>();
    occurrences.sort_by_key(|(offset, _)| *offset);
    let mut expanded = String::with_capacity(input.len());
    let mut cursor = 0;
    for (offset, block) in occurrences {
        if offset < cursor {
            continue;
        }
        expanded.push_str(&input[cursor..offset]);
        expanded.push_str(&block.text);
        cursor = offset + block.marker.len();
    }
    expanded.push_str(&input[cursor..]);
    expanded
}
