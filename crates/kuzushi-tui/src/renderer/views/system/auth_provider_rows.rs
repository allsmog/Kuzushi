use super::*;
use crate::ui_view_models::{AuthProviderRow, AuthProviderState};

pub(crate) fn auth_provider_line(row: &AuthProviderRow) -> Line<'static> {
    let (glyph, glyph_style, label_style) = match row.state {
        AuthProviderState::Connected => (" ✓ ", theme::success(), theme::success()),
        AuthProviderState::Missing => (" ✗ ", theme::danger(), theme::danger()),
        AuthProviderState::Inactive => (" · ", theme::subtle(), theme::muted()),
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, glyph_style),
        Span::raw(" "),
        Span::styled(format!("{:14}", row.name), theme::accent()),
        Span::styled(format!("{:11}", row.state.label()), label_style),
        Span::styled(row.detail.clone(), theme::muted()),
    ])
}
