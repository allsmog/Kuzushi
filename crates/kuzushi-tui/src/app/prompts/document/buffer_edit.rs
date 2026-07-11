use super::*;

impl ShellApp {
    pub(super) fn move_prompt_document_row(&mut self, delta: isize) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        document.cursor_row = document
            .cursor_row
            .saturating_add_signed(delta)
            .min(document.lines.len().saturating_sub(1));
        document.cursor_col = document.cursor_col.min(document.current_line_len());
        if document.cursor_row < document.top_row {
            document.top_row = document.cursor_row;
        }
        if document.cursor_row >= document.top_row + PAGE_ROWS {
            document.top_row = document.cursor_row + 1 - PAGE_ROWS;
        }
        document.pending_g = false;
    }

    pub(super) fn move_prompt_document_col(&mut self, delta: isize) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        document.cursor_col = document
            .cursor_col
            .saturating_add_signed(delta)
            .min(document.current_line_len());
    }

    pub(super) fn move_prompt_document_to_end(&mut self) {
        if let Some(document) = self.router.prompts_mut().document_mut() {
            document.cursor_row = document.lines.len().saturating_sub(1);
            document.cursor_col = 0;
            document.top_row = document.cursor_row.saturating_sub(PAGE_ROWS - 1);
            document.pending_g = false;
        }
    }

    pub(super) fn handle_prompt_document_g(&mut self) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        if document.pending_g {
            document.cursor_row = 0;
            document.cursor_col = 0;
            document.top_row = 0;
            document.pending_g = false;
        } else {
            document.pending_g = true;
        }
    }

    pub(super) fn clear_prompt_pending_g(&mut self) {
        if let Some(document) = self.router.prompts_mut().document_mut() {
            document.pending_g = false;
        }
    }

    pub(super) fn insert_prompt_document_char(&mut self, ch: char) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        let line = &mut document.lines[document.cursor_row];
        line.insert(char_to_byte_index(line, document.cursor_col), ch);
        document.cursor_col += 1;
        document.dirty = true;
    }

    pub(super) fn insert_prompt_document_newline(&mut self) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        let line = &mut document.lines[document.cursor_row];
        let tail = line.split_off(char_to_byte_index(line, document.cursor_col));
        document.cursor_row += 1;
        document.cursor_col = 0;
        document.lines.insert(document.cursor_row, tail);
        document.dirty = true;
    }

    pub(super) fn backspace_prompt_document(&mut self) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        if document.cursor_col > 0 {
            backspace_current_prompt_line(document);
        } else if document.cursor_row > 0 {
            join_prompt_line_with_previous(document);
        }
    }
}

fn backspace_current_prompt_line(document: &mut PromptDocumentState) {
    let line = &mut document.lines[document.cursor_row];
    let end = char_to_byte_index(line, document.cursor_col);
    let start = char_to_byte_index(line, document.cursor_col - 1);
    line.replace_range(start..end, "");
    document.cursor_col -= 1;
    document.dirty = true;
}

fn join_prompt_line_with_previous(document: &mut PromptDocumentState) {
    let removed = document.lines.remove(document.cursor_row);
    document.cursor_row -= 1;
    document.cursor_col = document.lines[document.cursor_row].chars().count();
    document.lines[document.cursor_row].push_str(&removed);
    document.dirty = true;
}

fn char_to_byte_index(value: &str, char_index: usize) -> usize {
    value
        .char_indices()
        .nth(char_index)
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}
