use super::*;
use crate::ui_view_models::{AuthProviderRow, AuthProviderTone};

/// `glyph name status detail` provider row. When the detail cell would
/// overflow the panel (narrow terminals), it drops to its own indented
/// line instead of being clipped off the right edge.
pub(crate) fn auth_provider_lines(row: &AuthProviderRow, width: u16) -> Vec<Line<'static>> {
    let inline = auth_provider_line(row);
    if inline.width() <= width as usize {
        return vec![inline];
    }
    let mut lines = vec![auth_provider_status_line(row)];
    lines.extend(auth_provider_detail_lines(row, width));
    lines
}

pub(crate) fn auth_provider_line(row: &AuthProviderRow) -> Line<'static> {
    let mut line = auth_provider_status_line(row);
    line.spans
        .push(Span::styled(row.cells[2].clone(), theme::muted()));
    line
}

fn auth_provider_status_line(row: &AuthProviderRow) -> Line<'static> {
    let (glyph, glyph_style, label_style) = auth_provider_tone_styles(row.tone);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, glyph_style),
        Span::raw(" "),
        Span::styled(format!("{:16}", row.cells[0]), theme::accent()),
        Span::styled(format!("{:11}", row.cells[1]), label_style),
    ])
}

fn auth_provider_detail_lines(row: &AuthProviderRow, width: u16) -> Vec<Line<'static>> {
    let indent = 5usize; // aligns under the provider name column
    let budget = (width as usize).saturating_sub(indent).max(8);
    wrap_text(&row.cells[2], budget)
        .into_iter()
        .map(|part| {
            Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(part, theme::muted()),
            ])
        })
        .collect()
}

fn auth_provider_tone_styles(
    tone: AuthProviderTone,
) -> (&'static str, ratatui::style::Style, ratatui::style::Style) {
    match tone {
        AuthProviderTone::Connected => (" ✓ ", theme::success(), theme::success()),
        AuthProviderTone::Missing => (" ✗ ", theme::danger(), theme::danger()),
        AuthProviderTone::Refreshable => (" ! ", theme::warn(), theme::warn()),
        AuthProviderTone::Incomplete => (" ! ", theme::warn(), theme::warn()),
    }
}
