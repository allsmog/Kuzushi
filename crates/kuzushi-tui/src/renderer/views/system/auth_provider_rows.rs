use super::*;
use crate::ui_view_models::{AuthProviderRow, AuthProviderTone};

pub(crate) fn auth_provider_line(row: &AuthProviderRow) -> Line<'static> {
    let (glyph, glyph_style, label_style) = match row.tone {
        AuthProviderTone::Connected => (" ✓ ", theme::success(), theme::success()),
        AuthProviderTone::Missing => (" ✗ ", theme::danger(), theme::danger()),
        AuthProviderTone::Inactive => (" · ", theme::subtle(), theme::muted()),
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, glyph_style),
        Span::raw(" "),
        Span::styled(format!("{:14}", row.cells[0]), theme::accent()),
        Span::styled(format!("{:11}", row.cells[1]), label_style),
        Span::styled(row.cells[2].clone(), theme::muted()),
    ])
}
