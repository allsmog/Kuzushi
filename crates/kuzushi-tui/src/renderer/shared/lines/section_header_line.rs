use super::*;

pub(crate) fn section_header_line(label: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label_text = format!("{} ", label.to_uppercase());
    let used = 1 + lead.chars().count() + label_text.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label_text, theme::label()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}
