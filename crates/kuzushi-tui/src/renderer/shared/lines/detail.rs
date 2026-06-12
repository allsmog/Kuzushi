use super::*;

pub(crate) fn detail(key: &str, value: &str) -> Line<'static> {
    // Mockup `kv(key, val, …)` from `design/mockups/config.jsx` /
    // `workspace.jsx` puts the key in c-muted and the value in c-primary
    // (and pads the key to a fixed column for alignment). The Ratatui
    // `detail` was emitting a label-color (bold blue) key + default-style
    // value, which read as a section header rather than a kv row. Use
    // muted+primary so detail rows blend into the mockup's denser feel.
    Line::from(vec![
        Span::styled(detail_key_column(key), theme::muted()),
        Span::styled(value.to_string(), theme::primary()),
    ])
}

/// `detail` for values that can run long (rationales, env summaries,
/// paths): wraps the value under the key column instead of letting the
/// row overflow off the right edge.
pub(crate) fn detail_wrapped(key: &str, value: &str, width: u16) -> Vec<Line<'static>> {
    let key_column = detail_key_column(key);
    let continuation = " ".repeat(key_column.chars().count());
    let budget = (width as usize)
        .saturating_sub(continuation.chars().count())
        .max(12);
    wrap_text(value, budget)
        .into_iter()
        .enumerate()
        .map(|(index, part)| {
            let lead = if index == 0 {
                key_column.clone()
            } else {
                continuation.clone()
            };
            Line::from(vec![
                Span::styled(lead, theme::muted()),
                Span::styled(part, theme::primary()),
            ])
        })
        .collect()
}

fn detail_key_column(key: &str) -> String {
    let key_pad = 18usize;
    if key.chars().count() >= key_pad {
        format!("{key} ")
    } else {
        let pad_chars = key_pad - key.chars().count();
        format!("{key}{}", " ".repeat(pad_chars + 1))
    }
}

pub(crate) fn divider(title: &str, width: u16) -> Line<'static> {
    // `design/mockups/_shared.jsx::sectionHeader` lays the rule out
    // left-aligned: ` ── LABEL ────...────`. The TUI used to center the
    // label between two rules, which read as a heavy decorative bar that
    // didn't match the lightweight muscle-memory feel of the mockups.
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{title} ");
    let used = 1 + lead.chars().count() + label.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

pub(crate) fn category_divider(name: &str, blurb: &str, width: u16) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let lead = "── ";
    let label = format!("{name} ");
    let blurb_text = format!("{blurb} ");
    let used = lead.chars().count() + label.chars().count() + blurb_text.chars().count();
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::styled(lead.to_string(), theme::subtle()),
        Span::styled(label, theme::label()),
        Span::styled(blurb_text, theme::muted()),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

pub(crate) fn blank() -> Line<'static> {
    Line::raw("")
}

pub(crate) fn muted(value: &str) -> Line<'static> {
    styled(value, theme::muted())
}

pub(crate) fn styled(value: &str, style: Style) -> Line<'static> {
    Line::styled(value.to_string(), style)
}

pub(crate) fn keybind_hint_line(pairs: &[(&str, &str)]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = vec![Span::raw(" ")];
    for (i, (key, hint)) in pairs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled((*key).to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled((*hint).to_string(), theme::muted()));
    }
    Line::from(spans)
}

#[cfg(test)]
mod detail_wrapped_tests {
    use super::*;

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn long_values_wrap_under_the_key_column() {
        let value = "operator-configured model is incompatible with the chosen runtime and \
no fallback model will ever be silently selected by kuzushi";
        let lines = detail_wrapped("rationale", value, 60);
        assert!(lines.len() > 1, "wraps: {lines:?}");
        assert!(text(&lines[0]).starts_with("rationale"));
        assert!(
            text(&lines[1]).starts_with("                   "),
            "continuation aligns under the value column: {:?}",
            text(&lines[1])
        );
        let joined: String = lines.iter().map(|l| text(l)).collect::<Vec<_>>().join(" ");
        assert!(joined.contains("silently selected"), "no content lost");
    }

    #[test]
    fn short_values_stay_single_line() {
        let lines = detail_wrapped("status", "ok", 80);
        assert_eq!(lines.len(), 1);
        assert_eq!(text(&lines[0]), format!("{:<19}ok", "status"));
    }
}
