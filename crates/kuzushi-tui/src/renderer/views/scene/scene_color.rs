//! The one colour bridge the scene renderer still needs: linear `[f32; 3]` (as
//! produced by `scene3d::render`) back to a truecolor ratatui `Color` for
//! emitting `▀` cells. Scene colours themselves are defined by
//! `scene3d::default_palette`.

use ratatui::style::Color;

/// `[f32; 3]` in `0..=1` to a truecolor ratatui `Color`.
pub(super) fn to_color(rgb: [f32; 3]) -> Color {
    Color::Rgb(
        (rgb[0].clamp(0.0, 1.0) * 255.0) as u8,
        (rgb[1].clamp(0.0, 1.0) * 255.0) as u8,
        (rgb[2].clamp(0.0, 1.0) * 255.0) as u8,
    )
}
