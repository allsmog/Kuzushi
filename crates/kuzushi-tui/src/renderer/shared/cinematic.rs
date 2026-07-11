use super::*;
use crate::theme::CinematicProfile;
use ratatui::buffer::{Buffer, Cell};
use ratatui::style::{Color, Modifier};

const FIX_KANJI: &str = "掛";

/// Apply the phase backdrop without replacing semantic cell backgrounds.
pub(crate) fn paint_cinematic_background(buffer: &mut Buffer, area: Rect) {
    paint_cinematic_background_for_profile(buffer, area, crate::theme::cinematic_profile());
}

pub(crate) fn paint_cinematic_background_for_profile(
    buffer: &mut Buffer,
    area: Rect,
    profile: CinematicProfile,
) {
    let Some(color) = profile.background() else {
        return;
    };
    visit_cells(buffer, area, |cell, _| {
        tint_owned_background(cell, profile, color)
    });
}

/// Tint alternating rows while leaving selection and status-chip backgrounds intact.
pub(crate) fn paint_cinematic_scanlines(buffer: &mut Buffer, area: Rect) {
    paint_cinematic_scanlines_for_profile(buffer, area, crate::theme::cinematic_profile());
}

pub(crate) fn paint_cinematic_scanlines_for_profile(
    buffer: &mut Buffer,
    area: Rect,
    profile: CinematicProfile,
) {
    let Some(color) = profile.scanline() else {
        return;
    };
    visit_cells(buffer, area, |cell, row| {
        if row % 2 == 1 {
            tint_owned_background(cell, profile, color);
        }
    });
}

/// Draw a faint Fix motif only in unused cells with non-semantic backgrounds.
pub(crate) fn paint_fix_watermark(buffer: &mut Buffer, area: Rect) {
    paint_fix_watermark_for_profile(buffer, area, crate::theme::cinematic_profile());
}

pub(crate) fn paint_fix_watermark_for_profile(
    buffer: &mut Buffer,
    area: Rect,
    profile: CinematicProfile,
) {
    let Some(color) = profile.watermark() else {
        return;
    };
    let width = display_width(FIX_KANJI) as u16;
    let Some(origin) = nearest_unused_span(buffer, area, width, profile) else {
        return;
    };
    paint_unused_kanji(buffer, area, origin, width, profile, color);
}

fn visit_cells(buffer: &mut Buffer, area: Rect, mut visit: impl FnMut(&mut Cell, u16)) {
    let clipped = area.intersection(*buffer.area());
    for y in clipped.top()..clipped.bottom() {
        for x in clipped.left()..clipped.right() {
            if let Some(cell) = buffer.cell_mut((x, y)) {
                visit(cell, y.saturating_sub(area.y));
            }
        }
    }
}

fn tint_owned_background(cell: &mut Cell, profile: CinematicProfile, color: Color) {
    if is_safe_backdrop_cell(cell) && profile.owns_background(cell.bg) {
        cell.set_bg(color);
    }
}

fn is_safe_backdrop_cell(cell: &Cell) -> bool {
    !cell.skip && !cell.modifier.intersects(Modifier::REVERSED)
}

fn centered_origin(area: Rect, width: u16, height: u16) -> (u16, u16) {
    (
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
    )
}

fn nearest_unused_span(
    buffer: &Buffer,
    area: Rect,
    width: u16,
    profile: CinematicProfile,
) -> Option<(u16, u16)> {
    let clipped = area.intersection(*buffer.area());
    if clipped.width < width || clipped.height == 0 {
        return None;
    }
    let center = centered_origin(clipped, width, 1);
    motif_positions(clipped, width)
        .filter(|position| motif_span_is_unused(buffer, clipped, *position, width, profile))
        .min_by_key(|position| motif_distance(*position, center))
}

fn motif_positions(area: Rect, width: u16) -> impl Iterator<Item = (u16, u16)> {
    let rightmost = area.right().saturating_sub(width);
    (area.top()..area.bottom()).flat_map(move |y| (area.left()..=rightmost).map(move |x| (x, y)))
}

fn motif_distance(position: (u16, u16), center: (u16, u16)) -> (u16, u16, u16, u16) {
    let horizontal = position.0.abs_diff(center.0);
    let vertical = position.1.abs_diff(center.1);
    (
        horizontal.saturating_add(vertical),
        vertical,
        position.1,
        position.0,
    )
}

fn paint_unused_kanji(
    buffer: &mut Buffer,
    area: Rect,
    origin: (u16, u16),
    width: u16,
    profile: CinematicProfile,
    color: Color,
) {
    if !motif_span_is_unused(buffer, area, origin, width, profile) {
        return;
    }
    let continuation_styles = (1..width)
        .map(|offset| {
            let position = (origin.0.saturating_add(offset), origin.1);
            (position, buffer[position].style())
        })
        .collect::<Vec<_>>();
    buffer.set_stringn(
        origin.0,
        origin.1,
        FIX_KANJI,
        width as usize,
        Style::default()
            .fg(color)
            .remove_modifier(Modifier::BOLD | Modifier::REVERSED),
    );
    for (position, style) in continuation_styles {
        buffer[position].set_style(style);
    }
}

fn motif_span_is_unused(
    buffer: &Buffer,
    area: Rect,
    origin: (u16, u16),
    width: u16,
    profile: CinematicProfile,
) -> bool {
    (0..width).all(|offset| {
        let position = (origin.0.saturating_add(offset), origin.1);
        area.contains(position.into())
            && buffer.area().contains(position.into())
            && motif_cell_is_unused(&buffer[position], profile)
    })
}

fn motif_cell_is_unused(cell: &Cell, profile: CinematicProfile) -> bool {
    cell.symbol().trim().is_empty()
        && is_safe_backdrop_cell(cell)
        && profile.owns_background(cell.bg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{cinematic_profile_for, ColorDepth, ThemeConfig, T_ACCENT};

    fn profile(depth: ColorDepth) -> CinematicProfile {
        cinematic_profile_for(ThemeConfig {
            color_depth: depth,
            no_color: depth == ColorDepth::None,
            ..ThemeConfig::default()
        })
    }

    #[test]
    fn backdrop_and_scanlines_preserve_semantic_backgrounds() {
        let area = Rect::new(0, 0, 4, 3);
        let mut buffer = Buffer::empty(area);
        buffer[(1, 1)].set_bg(T_ACCENT);
        buffer[(2, 1)].set_style(Style::default().add_modifier(Modifier::REVERSED));
        let profile = profile(ColorDepth::TrueColor);

        paint_cinematic_background_for_profile(&mut buffer, area, profile);
        paint_cinematic_scanlines_for_profile(&mut buffer, area, profile);

        assert_eq!(buffer[(0, 0)].bg, profile.background().unwrap());
        assert_eq!(buffer[(0, 1)].bg, profile.scanline().unwrap());
        assert_eq!(buffer[(1, 1)].bg, T_ACCENT);
        assert_eq!(buffer[(2, 1)].bg, Color::Reset);
    }

    #[test]
    fn effects_clip_to_buffer_and_requested_area() {
        let mut buffer = Buffer::empty(Rect::new(5, 5, 4, 3));
        let profile = profile(ColorDepth::TrueColor);

        paint_cinematic_background_for_profile(&mut buffer, Rect::new(3, 4, 4, 3), profile);

        assert_eq!(buffer[(5, 5)].bg, profile.background().unwrap());
        assert_eq!(buffer[(6, 5)].bg, profile.background().unwrap());
        assert_eq!(buffer[(7, 5)].bg, Color::Reset);
    }

    #[test]
    fn watermark_writes_only_blank_non_semantic_cells() {
        let area = Rect::new(0, 0, 20, 7);
        let profile = profile(ColorDepth::TrueColor);
        let width = display_width(FIX_KANJI) as u16;
        let origin = centered_origin(area, width, 1);
        let mut buffer = Buffer::empty(area);

        paint_fix_watermark_for_profile(&mut buffer, area, profile);

        assert_eq!(buffer[origin].symbol(), FIX_KANJI);
        assert_eq!(display_width(buffer[origin].symbol()), width as usize);
        assert_eq!(buffer[(origin.0 + 1, origin.1)].symbol(), " ");
        assert_eq!(buffer[origin].fg, profile.watermark().unwrap());

        let blocked_position = (origin.0 + 1, origin.1);
        let mut selected_buffer = Buffer::empty(area);
        selected_buffer[blocked_position].set_bg(T_ACCENT);
        paint_fix_watermark_for_profile(&mut selected_buffer, area, profile);
        assert_eq!(selected_buffer[blocked_position].symbol(), " ");
        assert_eq!(selected_buffer[blocked_position].bg, T_ACCENT);

        let mut reversed_buffer = Buffer::empty(area);
        reversed_buffer[blocked_position]
            .set_style(Style::default().add_modifier(Modifier::REVERSED));
        paint_fix_watermark_for_profile(&mut reversed_buffer, area, profile);
        assert_eq!(reversed_buffer[blocked_position].symbol(), " ");
        assert!(reversed_buffer[blocked_position]
            .modifier
            .contains(Modifier::REVERSED));

        let mut text_buffer = Buffer::empty(area);
        text_buffer[origin].set_char('X');
        paint_fix_watermark_for_profile(&mut text_buffer, area, profile);
        assert_eq!(text_buffer[origin].symbol(), "X");
    }

    #[test]
    fn kanji_watermark_fits_an_exact_double_width_span() {
        let area = Rect::new(0, 0, 2, 1);
        let mut buffer = Buffer::empty(area);

        paint_fix_watermark_for_profile(&mut buffer, area, profile(ColorDepth::TrueColor));

        assert_eq!(buffer[(0, 0)].symbol(), FIX_KANJI);
        assert_eq!(display_width(buffer[(0, 0)].symbol()), 2);
        assert_eq!(buffer[(1, 0)].symbol(), " ");
        assert_eq!(buffer.content().len(), 2);
    }

    #[test]
    fn occupied_center_uses_nearest_safe_double_width_span() {
        let area = Rect::new(0, 0, 8, 3);
        let mut buffer = Buffer::empty(area);
        let centered = centered_origin(area, 2, 1);
        buffer[centered].set_char('X');

        paint_fix_watermark_for_profile(&mut buffer, area, profile(ColorDepth::TrueColor));

        assert_eq!(buffer[centered].symbol(), "X");
        assert_eq!(buffer[(centered.0 + 1, centered.1)].symbol(), FIX_KANJI);
        assert_eq!(buffer[(centered.0 + 2, centered.1)].symbol(), " ");
    }

    #[test]
    fn off_profile_leaves_buffer_untouched() {
        let area = Rect::new(0, 0, 20, 7);
        let mut buffer = Buffer::empty(area);
        let original = buffer.clone();
        let profile = profile(ColorDepth::None);

        paint_cinematic_background_for_profile(&mut buffer, area, profile);
        paint_cinematic_scanlines_for_profile(&mut buffer, area, profile);
        paint_fix_watermark_for_profile(&mut buffer, area, profile);

        assert_eq!(buffer, original);
    }
}
