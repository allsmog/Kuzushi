//! Depth-stack navigation state for the Workbench review surface.
//!
//! An opt-in alternative to the four-pane focus ring (`WorkbenchPane`): instead
//! of scaling a wide cockpit down, the operator zooms through three depths,
//! unwound one level per `Esc`:
//!
//! ```text
//! List    — every finding (+ a peek preview)
//! Finding — spine (rail) · data-flow ladder (focal) · triage/proof drawer
//! Record  — one triage/proof entry or scanner log, full-body
//! ```
//!
//! The state machine is pure and owns only depth-stack concerns (depth, focused
//! pane, drawer tab, leg/row cursors, scroll). Finding *selection* stays on the
//! authoritative findings route state, so the DETAILS/legs always reflect
//! the truly selected finding; selection moves come back as [`NavEffect`]s the
//! app applies through its existing cursor helpers.

mod kinds;
mod scroll;

pub use kinds::{DrawerTab, FindingPane, NavBounds, NavEffect, WorkbenchDepth};
pub use scroll::BoundedScroll;

use crossterm::event::{KeyCode, KeyEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkbenchNav {
    pub depth: WorkbenchDepth,
    pub pane: FindingPane,
    pub tab: DrawerTab,
    pub leg: usize,
    pub drawer_row: usize,
    /// At most one ladder leg expands its data-flow nodes (accordion).
    pub expanded_leg: Option<usize>,
    pub peek: bool,
    pub ladder_scroll: BoundedScroll,
    pub drawer_scroll: BoundedScroll,
    pub record_scroll: BoundedScroll,
}

impl Default for WorkbenchNav {
    fn default() -> Self {
        Self {
            depth: WorkbenchDepth::List,
            pane: FindingPane::Ladder,
            tab: DrawerTab::Triage,
            leg: 0,
            drawer_row: 0,
            expanded_leg: Some(0),
            peek: false,
            ladder_scroll: BoundedScroll::default(),
            drawer_scroll: BoundedScroll::default(),
            record_scroll: BoundedScroll::default(),
        }
    }
}

impl WorkbenchNav {
    pub fn apply_key(&mut self, key: KeyEvent, bounds: NavBounds) -> NavEffect {
        match self.depth {
            WorkbenchDepth::List => self.list_key(key.code),
            WorkbenchDepth::Finding => self.finding_key(key.code, bounds),
            WorkbenchDepth::Record => self.record_key(key.code, bounds),
        }
    }

    // ── Depth 0: list ────────────────────────────────────────────────────────
    fn list_key(&mut self, code: KeyCode) -> NavEffect {
        match code {
            KeyCode::Char('j') => NavEffect::SelectStep(1),
            KeyCode::Char('k') => NavEffect::SelectStep(-1),
            KeyCode::Char('g') => NavEffect::SelectJump(true),
            KeyCode::Char('G') => NavEffect::SelectJump(false),
            KeyCode::Char(' ') => {
                self.peek = !self.peek;
                NavEffect::Handled
            }
            KeyCode::Enter => self.enter_finding(),
            KeyCode::Esc if self.peek => {
                self.peek = false;
                NavEffect::Handled
            }
            KeyCode::Esc => NavEffect::Leave,
            _ => NavEffect::Ignored,
        }
    }

    fn enter_finding(&mut self) -> NavEffect {
        self.depth = WorkbenchDepth::Finding;
        self.pane = FindingPane::Ladder;
        self.peek = false;
        self.reset_finding_state();
        NavEffect::Handled
    }

    // ── Depth 1: finding ─────────────────────────────────────────────────────
    fn finding_key(&mut self, code: KeyCode, bounds: NavBounds) -> NavEffect {
        match code {
            KeyCode::Tab => self.set_pane(self.pane.next()),
            KeyCode::BackTab => self.set_pane(self.pane.prev()),
            KeyCode::Char('j') => self.move_in_pane(1, bounds),
            KeyCode::Char('k') => self.move_in_pane(-1, bounds),
            KeyCode::Char('g') => self.jump_in_pane(true, bounds),
            KeyCode::Char('G') => self.jump_in_pane(false, bounds),
            KeyCode::Char('e') => self.toggle_leg(),
            KeyCode::Char('[') => self.switch_tab(self.tab.prev()),
            KeyCode::Char(']') => self.switch_tab(self.tab.next()),
            KeyCode::Char('J') => self.lateral(1),
            KeyCode::Char('K') => self.lateral(-1),
            KeyCode::Char('z') => self.zoom(),
            KeyCode::Enter => self.finding_enter(),
            KeyCode::Esc => {
                self.depth = WorkbenchDepth::List;
                NavEffect::Handled
            }
            _ => NavEffect::Ignored,
        }
    }

    fn set_pane(&mut self, pane: FindingPane) -> NavEffect {
        self.pane = pane;
        NavEffect::Handled
    }

    fn switch_tab(&mut self, tab: DrawerTab) -> NavEffect {
        self.tab = tab;
        self.drawer_row = 0;
        self.drawer_scroll = BoundedScroll::default();
        NavEffect::Handled
    }

    fn move_in_pane(&mut self, delta: isize, bounds: NavBounds) -> NavEffect {
        match self.pane {
            FindingPane::Spine => NavEffect::SelectStep(delta),
            FindingPane::Ladder => {
                self.leg = step(self.leg, delta, bounds.legs);
                self.ladder_scroll.scroll_by(delta);
                NavEffect::Handled
            }
            FindingPane::Drawer => {
                self.drawer_row = step(self.drawer_row, delta, bounds.drawer_rows);
                self.drawer_scroll.scroll_by(delta);
                NavEffect::Handled
            }
        }
    }

    fn jump_in_pane(&mut self, to_start: bool, bounds: NavBounds) -> NavEffect {
        match self.pane {
            FindingPane::Spine => NavEffect::SelectJump(to_start),
            FindingPane::Ladder => {
                self.leg = edge(to_start, bounds.legs);
                self.ladder_scroll.jump(to_start);
                NavEffect::Handled
            }
            FindingPane::Drawer => {
                self.drawer_row = edge(to_start, bounds.drawer_rows);
                self.drawer_scroll.jump(to_start);
                NavEffect::Handled
            }
        }
    }

    fn finding_enter(&mut self) -> NavEffect {
        match self.pane {
            FindingPane::Ladder => self.toggle_leg(),
            FindingPane::Drawer => self.zoom(),
            FindingPane::Spine => self.set_pane(FindingPane::Ladder),
        }
    }

    fn toggle_leg(&mut self) -> NavEffect {
        self.expanded_leg = (self.expanded_leg != Some(self.leg)).then_some(self.leg);
        NavEffect::Handled
    }

    /// Walk to an adjacent finding without unwinding to the list.
    fn lateral(&mut self, delta: isize) -> NavEffect {
        self.reset_finding_state();
        NavEffect::SelectStep(delta)
    }

    fn zoom(&mut self) -> NavEffect {
        self.depth = WorkbenchDepth::Record;
        self.record_scroll = BoundedScroll::default();
        NavEffect::Handled
    }

    fn reset_finding_state(&mut self) {
        self.leg = 0;
        self.expanded_leg = Some(0);
        self.drawer_row = 0;
        self.ladder_scroll = BoundedScroll::default();
        self.drawer_scroll = BoundedScroll::default();
        self.record_scroll = BoundedScroll::default();
    }

    // ── Depth 2: record zoom ─────────────────────────────────────────────────
    fn record_key(&mut self, code: KeyCode, bounds: NavBounds) -> NavEffect {
        match code {
            KeyCode::Char('j') => self.scroll_record(1),
            KeyCode::Char('k') => self.scroll_record(-1),
            KeyCode::Char('g') => {
                self.record_scroll.scroll_to_top();
                NavEffect::Handled
            }
            KeyCode::Char('G') => {
                self.record_scroll.scroll_to_bottom();
                NavEffect::Handled
            }
            KeyCode::Char('J') => self.step_record(1, bounds),
            KeyCode::Char('K') => self.step_record(-1, bounds),
            KeyCode::Char('y') => NavEffect::Yank,
            KeyCode::Esc => {
                self.depth = WorkbenchDepth::Finding;
                NavEffect::Handled
            }
            _ => NavEffect::Ignored,
        }
    }

    fn scroll_record(&mut self, delta: isize) -> NavEffect {
        self.record_scroll.scroll_by(delta);
        NavEffect::Handled
    }

    fn step_record(&mut self, delta: isize, bounds: NavBounds) -> NavEffect {
        self.drawer_row = step(self.drawer_row, delta, bounds.drawer_rows);
        self.record_scroll = BoundedScroll::default();
        NavEffect::Handled
    }
}

fn step(cursor: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta < 0 {
        cursor.saturating_sub(delta.unsigned_abs())
    } else {
        (cursor + delta as usize).min(len - 1)
    }
}

fn edge(to_start: bool, len: usize) -> usize {
    if to_start {
        0
    } else {
        len.saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn bounds() -> NavBounds {
        NavBounds {
            legs: 4,
            drawer_rows: 6,
        }
    }

    #[test]
    fn enter_from_list_opens_finding_focused_on_ladder() {
        let mut nav = WorkbenchNav::default();
        let effect = nav.apply_key(key(KeyCode::Enter), bounds());
        assert_eq!(nav.depth, WorkbenchDepth::Finding);
        assert_eq!(nav.pane, FindingPane::Ladder);
        assert_eq!(effect, NavEffect::Handled);
    }

    #[test]
    fn list_movement_delegates_selection_to_the_app() {
        let mut nav = WorkbenchNav::default();
        assert_eq!(
            nav.apply_key(key(KeyCode::Char('j')), bounds()),
            NavEffect::SelectStep(1)
        );
        assert_eq!(
            nav.apply_key(key(KeyCode::Char('G')), bounds()),
            NavEffect::SelectJump(false)
        );
    }

    #[test]
    fn tab_cycles_spine_ladder_drawer() {
        let mut nav = WorkbenchNav {
            depth: WorkbenchDepth::Finding,
            ..Default::default()
        };
        nav.apply_key(key(KeyCode::Tab), bounds());
        assert_eq!(nav.pane, FindingPane::Drawer);
        nav.apply_key(key(KeyCode::Tab), bounds());
        assert_eq!(nav.pane, FindingPane::Spine);
    }

    #[test]
    fn esc_unwinds_exactly_one_depth() {
        let mut nav = WorkbenchNav {
            depth: WorkbenchDepth::Record,
            ..Default::default()
        };
        nav.apply_key(key(KeyCode::Esc), bounds());
        assert_eq!(nav.depth, WorkbenchDepth::Finding);
        nav.apply_key(key(KeyCode::Esc), bounds());
        assert_eq!(nav.depth, WorkbenchDepth::List);
    }

    #[test]
    fn lateral_resets_leg_and_asks_the_app_to_move_selection() {
        let mut nav = WorkbenchNav {
            depth: WorkbenchDepth::Finding,
            leg: 3,
            ..Default::default()
        };
        let effect = nav.apply_key(key(KeyCode::Char('J')), bounds());
        assert_eq!(effect, NavEffect::SelectStep(1));
        assert_eq!(nav.leg, 0);
        assert_eq!(nav.depth, WorkbenchDepth::Finding);
    }

    #[test]
    fn ladder_leg_cursor_never_runs_past_the_ends() {
        let mut nav = WorkbenchNav {
            depth: WorkbenchDepth::Finding,
            pane: FindingPane::Ladder,
            ..Default::default()
        };
        for _ in 0..99 {
            nav.apply_key(key(KeyCode::Char('j')), bounds());
        }
        assert_eq!(nav.leg, 3);
    }
}
