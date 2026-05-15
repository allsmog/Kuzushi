pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::scan_status;
use crate::ui_view_models::ModuleRunStatusKind;

/// Cycle through braille spinner frames using the projected status tick.
/// Tests use `tick = 0` (frame `⠿`) for determinism.
pub(crate) const SPINNER_FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];

pub(crate) fn run_state_glyph(status: ModuleRunStatusKind, tick: usize) -> &'static str {
    match status {
        ModuleRunStatusKind::Aborting | ModuleRunStatusKind::Failed => "✗",
        ModuleRunStatusKind::Running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        ModuleRunStatusKind::Done => "✓",
        ModuleRunStatusKind::Idle => "●",
    }
}

pub(crate) fn run_state_style(status: ModuleRunStatusKind) -> Style {
    match status {
        ModuleRunStatusKind::Aborting | ModuleRunStatusKind::Running => theme::warn(),
        ModuleRunStatusKind::Failed => theme::danger(),
        ModuleRunStatusKind::Done => theme::success(),
        ModuleRunStatusKind::Idle => theme::accent(),
    }
}
