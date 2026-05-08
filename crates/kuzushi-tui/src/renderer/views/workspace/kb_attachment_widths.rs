use super::*;

pub(crate) fn kb_attachment_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let id = 14;
    let kind = 4;
    let source = if total < 88 { 24 } else { 36 };
    let gaps = 6;
    let status = total.saturating_sub(id + kind + source + gaps).max(16);
    vec![id, kind, source, status]
}
