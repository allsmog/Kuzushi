pub(in crate::renderer) use super::*;
pub(crate) use crate::ui_view_models::scan_status;

/// Cycle through braille spinner frames using `tick` as the index source.
/// Pass `app.spinner_phase as usize` so the animation advances on the event
/// loop's ~100ms extracted shell tick. Tests use `spinner_phase = 0` (frame `⠿`)
/// for determinism.
pub(crate) const SPINNER_FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];

pub(crate) fn run_state_glyph(
    scan: Option<&ScanPanelState>,
    tool_running: bool,
    tick: usize,
) -> &'static str {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => "✗",
        Some(scan) if scan.running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        Some(scan) if scan.error.is_some() => "✗",
        Some(_) => "✓",
        None if tool_running => SPINNER_FRAMES[tick % SPINNER_FRAMES.len()],
        None => "●",
    }
}

pub(crate) fn run_state_style(scan: Option<&ScanPanelState>, tool_running: bool) -> Style {
    match scan {
        Some(scan) if scan.running && scan.abort_requested => theme::warn(),
        Some(scan) if scan.running => theme::warn(),
        Some(scan) if scan.error.is_some() => theme::danger(),
        Some(_) => theme::success(),
        None if tool_running => theme::warn(),
        None => theme::accent(),
    }
}
