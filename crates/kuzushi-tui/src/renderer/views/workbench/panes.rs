//! Pure pane-body line builders for the Workbench command center. Shared by the
//! frame renderer (each list drawn inside a bordered `Block`) and the plain
//! `workbench_lines` path (each list stacked under a text divider).

use super::*;
use ratatui::prelude::{Line, Span};

mod center;
mod findings;
mod hunt;
mod phase;
mod review_queue;
mod ship;
mod source;

pub(super) use center::center_pane_lines;
pub(super) use hunt::hunt_control_lines;
pub(super) use phase::{
    terrain_attack_surface_lines, terrain_material_lines, terrain_visual_lines,
};
pub(super) use review_queue::review_queue_pane_lines;
pub(super) use ship::{ship_chain_lines, ship_export_lines, ship_patch_lines};
pub(super) use source::{source_pane_lines, source_title};

pub(super) fn sep() -> Span<'static> {
    Span::styled(theme::STATUS_SEPARATOR, theme::subtle())
}

fn pane_empty_state(
    glyph_label: &str,
    explanations: &[&str],
    ctas: &[(&str, &str)],
) -> Vec<Line<'static>> {
    empty_state_panel(glyph_label, explanations, ctas)
}

fn command_hint(command: &str, label: &str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled("  · ", theme::muted()),
        Span::styled(
            fit(command, width.saturating_sub(label.len() + 8).max(8)),
            theme::label(),
        ),
        Span::raw("  "),
        Span::styled(label.to_string(), theme::muted()),
    ])
}
