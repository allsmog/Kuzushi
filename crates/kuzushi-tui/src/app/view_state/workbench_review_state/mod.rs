#[cfg(test)]
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::ListState;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkbenchReviewState {
    pub cursor: usize,
    pub mode: ReviewMode,
    pub frame: Vec<ReviewRow>,
    pub ledger_scroll: ListState,
    pub read_watermark: u64,
    pub generation: u64,
    pub pending: Option<PendingDecision>,
    /// Backlog preset: untriaged-only rows in severity-first order with
    /// one-key decisions. Explicit operator toggle — the canonical
    /// confidence-first shell sort stays the default.
    pub backlog: bool,
    /// Review decisions saved this shell session (any path, not just
    /// one-key); surfaces as the backlog session counter.
    pub session_decided: usize,
    /// Backlog severity filter (`s` cycles critical→high→medium→low→off).
    pub backlog_severity: Option<&'static str>,
    /// Backlog tool filter (`t` cycles the tools present in the ledger).
    pub backlog_tool: Option<String>,
    /// Armed bulk-defer confirmation: `X` arms it, a second `X` executes,
    /// any other backlog action disarms it. Never defers without a confirm.
    pub backlog_confirm_bulk: bool,
    /// Last backlog decision batch for single-level undo. Each entry
    /// carries the finding AS DECIDED (a decision can push the row out of
    /// the live projection, so undo must not depend on it) plus the prior
    /// latest verdict. Undo appends the inverse records — history is never
    /// deleted; the latest-decision-wins fold makes an append a reversal.
    pub backlog_last_batch: Vec<BacklogUndoEntry>,
    /// Item 13: incremental search over the visible queue. Free text covers
    /// finding text, evidence, and sources; textual facets cover severity,
    /// source/path, actor, confidence, and canonical status.
    pub search_query: String,
    /// True while the palette-style capture owns typing (`/` opens it) —
    /// keys never leak into the composer.
    pub search_capture: bool,
}

impl WorkbenchReviewState {
    pub(crate) fn open_search_capture(&mut self) {
        self.search_capture = true;
    }

    pub(crate) fn close_search_capture(&mut self, keep_query: bool) {
        self.search_capture = false;
        if !keep_query {
            self.search_query.clear();
        }
    }

    pub(crate) fn push_search_char(&mut self, character: char) {
        self.search_query.push(character);
    }

    pub(crate) fn pop_search_char(&mut self) {
        self.search_query.pop();
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BacklogUndoEntry {
    pub finding: kuzushi_core::Finding,
    pub alias: Option<String>,
    pub prior_verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRow {
    pub stable_fp: String,
    pub observation_hash: String,
    pub snapshot_hash: String,
    pub blob_hash: Option<String>,
    pub byte_span: Option<(u64, u64)>,
    pub display_path: String,
    pub display_line: u32,
    pub code_snippet: Vec<String>,
    pub trace_hops: Vec<String>,
    pub attestations: Vec<String>,
    pub verdict: String,
    pub confidence: u8,
    pub justification: Option<String>,
    pub provenance_refs: Vec<String>,
    pub projection_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewMode {
    Browse,
    #[cfg(test)]
    DeepTrace,
    #[cfg(test)]
    TriageDraft {
        buffer: String,
        cursor: usize,
        target_fp: String,
        read_watermark: u64,
    },
    #[cfg(test)]
    SuppressDraft {
        buffer: String,
        cursor: usize,
        target_fp: String,
        read_watermark: u64,
    },
    Conflict {
        message: String,
        target_fp: String,
    },
}

impl Default for ReviewMode {
    fn default() -> Self {
        Self::Browse
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDecision {
    pub command_id: String,
    pub target_fp: String,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewCommand {
    DecideTriage {
        stable_fp: String,
        read_watermark: u64,
        justification: String,
    },
    Suppress {
        stable_fp: String,
        read_watermark: u64,
        reason: String,
    },
}

impl WorkbenchReviewState {
    #[cfg(test)]
    pub fn replace_frame(&mut self, frame: Vec<ReviewRow>, read_watermark: u64, generation: u64) {
        self.frame = frame;
        self.read_watermark = read_watermark;
        self.generation = generation;
        self.cursor = self.cursor.min(self.frame.len().saturating_sub(1));
        self.ledger_scroll.select(Some(self.cursor));
    }

    #[cfg(test)]
    pub fn selected(&self) -> Option<&ReviewRow> {
        self.frame.get(self.cursor)
    }

    pub fn read_watermark_for(&self, stable_fp: &str) -> Option<u64> {
        #[cfg(test)]
        if let Some(read_watermark) = match &self.mode {
            ReviewMode::TriageDraft {
                target_fp,
                read_watermark,
                ..
            }
            | ReviewMode::SuppressDraft {
                target_fp,
                read_watermark,
                ..
            } if target_fp == stable_fp => Some(*read_watermark),
            _ => None,
        } {
            return Some(read_watermark);
        }

        self.frame
            .iter()
            .any(|row| row.stable_fp == stable_fp)
            .then_some(self.read_watermark)
    }

    #[cfg(test)]
    pub fn route_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        match mode_kind(&self.mode) {
            ModeKind::TriageDraft => self.route_triage_key(key),
            ModeKind::SuppressDraft => self.route_suppress_key(key),
            ModeKind::Blocking => self.route_blocking_key(key),
            ModeKind::Browse => self.route_browse_key(key),
        }
    }

    #[cfg(test)]
    fn route_browse_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => self.move_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_cursor(-1),
            KeyCode::Char('g') => self.jump(true),
            KeyCode::Char('G') => self.jump(false),
            KeyCode::Tab | KeyCode::Char('d') => self.toggle_deep_trace(),
            KeyCode::Char('t') => self.begin_triage(),
            KeyCode::Char('x') => self.begin_suppression(),
            KeyCode::Esc if self.mode == ReviewMode::DeepTrace => self.mode = ReviewMode::Browse,
            _ => {}
        }
        None
    }

    #[cfg(test)]
    fn route_triage_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        self.edit_draft(key, DraftKind::Triage)
    }

    #[cfg(test)]
    fn route_suppress_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        self.edit_draft(key, DraftKind::Suppress)
    }

    #[cfg(test)]
    fn route_blocking_key(&mut self, key: KeyEvent) -> Option<ReviewCommand> {
        if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
            self.mode = ReviewMode::Browse;
            self.pending = None;
        }
        None
    }

    #[cfg(test)]
    fn move_cursor(&mut self, delta: isize) {
        if self.frame.is_empty() {
            self.cursor = 0;
            self.ledger_scroll.select(None);
            return;
        }
        let last = self.frame.len() as isize - 1;
        self.cursor = (self.cursor as isize + delta).clamp(0, last) as usize;
        self.ledger_scroll.select(Some(self.cursor));
    }

    #[cfg(test)]
    fn jump(&mut self, to_start: bool) {
        self.cursor = if to_start {
            0
        } else {
            self.frame.len().saturating_sub(1)
        };
        self.ledger_scroll.select(Some(self.cursor));
    }

    #[cfg(test)]
    fn toggle_deep_trace(&mut self) {
        self.mode = match self.mode {
            ReviewMode::DeepTrace => ReviewMode::Browse,
            _ => ReviewMode::DeepTrace,
        };
    }

    #[cfg(test)]
    fn begin_triage(&mut self) {
        let Some(row) = self.selected() else {
            return;
        };
        let buffer = row.justification.clone().unwrap_or_default();
        self.mode = ReviewMode::TriageDraft {
            cursor: buffer.chars().count(),
            buffer,
            target_fp: row.stable_fp.clone(),
            read_watermark: self.read_watermark,
        };
    }

    #[cfg(test)]
    fn begin_suppression(&mut self) {
        let Some(row) = self.selected() else {
            return;
        };
        self.mode = ReviewMode::SuppressDraft {
            buffer: String::new(),
            cursor: 0,
            target_fp: row.stable_fp.clone(),
            read_watermark: self.read_watermark,
        };
    }

    #[cfg(test)]
    fn edit_draft(&mut self, key: KeyEvent, kind: DraftKind) -> Option<ReviewCommand> {
        match key.code {
            KeyCode::Esc => {
                self.mode = ReviewMode::Browse;
                None
            }
            KeyCode::Enter => self.commit_draft(kind),
            _ => {
                edit_active_buffer(&mut self.mode, key.code);
                None
            }
        }
    }

    #[cfg(test)]
    fn commit_draft(&mut self, kind: DraftKind) -> Option<ReviewCommand> {
        match std::mem::replace(&mut self.mode, ReviewMode::Browse) {
            ReviewMode::TriageDraft {
                buffer,
                target_fp,
                read_watermark,
                ..
            } => non_empty(buffer).map(|justification| ReviewCommand::DecideTriage {
                stable_fp: target_fp,
                read_watermark,
                justification,
            }),
            ReviewMode::SuppressDraft {
                buffer,
                target_fp,
                read_watermark,
                ..
            } if kind == DraftKind::Suppress => {
                non_empty(buffer).map(|reason| ReviewCommand::Suppress {
                    stable_fp: target_fp,
                    read_watermark,
                    reason,
                })
            }
            other => {
                self.mode = other;
                None
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DraftKind {
    Triage,
    Suppress,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModeKind {
    Browse,
    TriageDraft,
    SuppressDraft,
    Blocking,
}

#[cfg(test)]
fn mode_kind(mode: &ReviewMode) -> ModeKind {
    match mode {
        ReviewMode::Browse | ReviewMode::DeepTrace => ModeKind::Browse,
        ReviewMode::TriageDraft { .. } => ModeKind::TriageDraft,
        ReviewMode::SuppressDraft { .. } => ModeKind::SuppressDraft,
        ReviewMode::Conflict { .. } => ModeKind::Blocking,
    }
}

#[cfg(test)]
fn edit_active_buffer(mode: &mut ReviewMode, code: KeyCode) {
    let Some((buffer, cursor)) = draft_parts(mode) else {
        return;
    };
    match code {
        KeyCode::Left => *cursor = cursor.saturating_sub(1),
        KeyCode::Right => *cursor = (*cursor + 1).min(buffer.chars().count()),
        KeyCode::Home => *cursor = 0,
        KeyCode::End => *cursor = buffer.chars().count(),
        KeyCode::Backspace if *cursor > 0 => {
            *cursor -= 1;
            let at = byte_index(buffer, *cursor);
            buffer.remove(at);
        }
        KeyCode::Delete if *cursor < buffer.chars().count() => {
            let at = byte_index(buffer, *cursor);
            buffer.remove(at);
        }
        KeyCode::Char(c) => {
            let at = byte_index(buffer, *cursor);
            buffer.insert(at, c);
            *cursor += 1;
        }
        _ => {}
    }
}

#[cfg(test)]
fn draft_parts(mode: &mut ReviewMode) -> Option<(&mut String, &mut usize)> {
    match mode {
        ReviewMode::TriageDraft { buffer, cursor, .. }
        | ReviewMode::SuppressDraft { buffer, cursor, .. } => Some((buffer, cursor)),
        _ => None,
    }
}

#[cfg(test)]
fn byte_index(value: &str, char_pos: usize) -> usize {
    value
        .char_indices()
        .nth(char_pos)
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

#[cfg(test)]
fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

#[cfg(test)]
mod tests;
