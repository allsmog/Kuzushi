use super::{char_index_to_byte, graphemes, EditorState, PastedBlock, Range};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone)]
pub(crate) struct PasteInspection {
    block: PastedBlock,
    pub(crate) line: usize,
    pub(crate) column: usize,
}

impl PasteInspection {
    pub(crate) fn text(&self) -> &str {
        &self.block.text
    }

    pub(crate) fn title(&self) -> &str {
        &self.block.marker
    }

    fn navigate(&mut self, key: KeyCode) {
        match key {
            KeyCode::Up => self.line = self.line.saturating_sub(1),
            KeyCode::Down => self.line = (self.line + 1).min(self.text().split('\n').count() - 1),
            KeyCode::Left => self.column = self.column.saturating_sub(1),
            KeyCode::Right => self.column = (self.column + 1).min(self.text().len()),
            KeyCode::Home => {
                self.line = 0;
                self.column = 0;
            }
            KeyCode::End => self.line = self.text().split('\n').count() - 1,
            _ => (),
        }
    }
}

impl EditorState {
    pub(crate) fn has_pasted_blocks(&self) -> bool {
        !self.pasted_blocks.is_empty()
    }

    pub(super) fn atomic_floor(&self, cursor: usize) -> usize {
        self.pasted_blocks
            .iter()
            .find(|block| block.range.start < cursor && cursor < block.range.end)
            .map_or(cursor, |block| {
                graphemes::floor(&self.input, block.range.start)
            })
    }

    pub(super) fn atomic_ceil(&self, cursor: usize) -> usize {
        self.pasted_blocks
            .iter()
            .find(|block| block.range.start < cursor && cursor < block.range.end)
            .map_or(cursor, |block| {
                graphemes::ceil(&self.input, block.range.end)
            })
    }

    pub(super) fn remember_paste_edit(&mut self) {
        if self.has_pasted_blocks() {
            self.push_paste_undo();
        }
    }

    pub(super) fn push_paste_undo(&mut self) {
        self.last_cleared_input = None;
        self.last_cleared_pasted_blocks.clear();
        self.paste_undo.push(self.snapshot_input());
    }

    pub(crate) fn paste_inspection(&self) -> Option<&PasteInspection> {
        self.paste_inspection.as_ref()
    }

    pub(crate) fn inspect_paste_at_cursor(&mut self) -> bool {
        let Some(block) = self.paste_at_cursor().cloned() else {
            return false;
        };
        self.paste_inspection = Some(PasteInspection {
            block,
            line: 0,
            column: 0,
        });
        true
    }

    pub(crate) fn handle_paste_inspection_key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd')) {
            return false;
        }
        if !key.modifiers.is_empty() {
            return self.paste_inspection.is_some();
        }
        let Some(mut inspection) = self.paste_inspection.take() else {
            return false;
        };
        match key.code {
            KeyCode::Esc => (),
            KeyCode::Enter | KeyCode::Char('e') => {
                self.cursor = inspection.block.range.start;
                self.expand_paste_at_cursor();
            }
            KeyCode::Delete | KeyCode::Backspace => self.replace_edit(inspection.block.range, ""),
            _ => {
                inspection.navigate(key.code);
                self.paste_inspection = Some(inspection);
            }
        }
        true
    }

    pub(super) fn replace_edit(&mut self, range: Range<usize>, value: &str) {
        let range = self.atomic_floor(range.start)..self.atomic_ceil(range.end);
        if self
            .pasted_blocks
            .iter()
            .any(|block| overlaps(&block.range, &range))
        {
            self.remember_paste_edit();
        }
        let bytes = char_index_to_byte(&self.input, range.start)
            ..char_index_to_byte(&self.input, range.end);
        let inserted = value.chars().count();
        self.input.replace_range(bytes, value);
        self.pasted_blocks
            .retain_mut(|block| relocate(block, &range, inserted));
        self.cursor = graphemes::ceil(&self.input, range.start + inserted);
        self.history_index = None;
        self.touch_completion_preview();
    }

    pub(crate) fn expand_paste_at_cursor(&mut self) -> bool {
        let Some(block) = self.paste_at_cursor().cloned() else {
            return false;
        };
        self.replace_edit(block.range, &block.text);
        true
    }

    fn paste_at_cursor(&self) -> Option<&PastedBlock> {
        self.pasted_blocks
            .iter()
            .find(|block| block.range.contains(&self.cursor))
            .or_else(|| {
                self.pasted_blocks
                    .iter()
                    .find(|block| block.range.end == self.cursor)
            })
    }
}

fn overlaps(block: &Range<usize>, edit: &Range<usize>) -> bool {
    block.start < edit.end && edit.start < block.end
}

fn relocate(block: &mut PastedBlock, edit: &Range<usize>, inserted: usize) -> bool {
    if block.range.end <= edit.start {
        return true;
    }
    if overlaps(&block.range, edit) {
        return false;
    }
    block.range.start = block.range.start - edit.len() + inserted;
    block.range.end = block.range.end - edit.len() + inserted;
    true
}
