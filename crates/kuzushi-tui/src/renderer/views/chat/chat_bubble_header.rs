use super::*;

pub(crate) fn chat_bubble_header(tag: &str, tag_style: Style, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let used = 1 + tag.chars().count() + 2;
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(tag.to_string(), tag_style),
        Span::raw(" "),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}
