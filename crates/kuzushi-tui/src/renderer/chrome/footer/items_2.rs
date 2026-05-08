use super::*;

pub(crate) fn justify_prefer_right(left: String, right: String, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if right.is_empty() {
        return fit(&left, width);
    }
    let right = fit(&right, width);
    let right_len = right.chars().count();
    if right_len + 1 >= width {
        return right;
    }
    let left_budget = width.saturating_sub(right_len + 1);
    let left = fit(&left, left_budget);
    let left_len = left.chars().count();
    let pad = width.saturating_sub(left_len + right_len);
    format!("{left}{}{}", " ".repeat(pad), right)
}

pub(crate) fn render_keybind_footer(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    let mut lines = Vec::new();
    lines.push(Line::styled(
        theme::RULE_CHAR.repeat(area.width as usize),
        theme::subtle(),
    ));

    if area.height > 1 {
        lines.push(keybindings_line(app, area.width as usize));
    }

    render_lines(frame, area, lines);
}

pub(crate) fn keybindings_line(app: &ShellApp, width: usize) -> Line<'static> {
    const TAIL: &str = "help more";
    // Reserve enough headroom so the `help more` overflow chip always fits
    // (`   ` separator + the chip itself).
    let reserve = 3 + TAIL.chars().count();
    let bindings = keybindings(app);
    let bindings_len = bindings.len();

    let mut spans: Vec<Span<'static>> = Vec::new();
    spans.push(Span::raw(" "));
    let mut used = 1usize;
    let mut overflow = false;
    let mut placed = 0usize;

    for (i, (key, hint)) in bindings.into_iter().enumerate() {
        let pair = format!("{key} {hint}");
        let sep = if placed == 0 { 0 } else { 3 };
        let need = sep + pair.chars().count();
        // Last binding doesn't need to leave room for the tail chip — there
        // is nothing left to point at.
        let cap = if i + 1 == bindings_len {
            width.saturating_sub(1)
        } else {
            width.saturating_sub(reserve + 1)
        };
        if used + need > cap && placed > 0 {
            overflow = true;
            break;
        }
        if placed > 0 {
            spans.push(Span::raw("   "));
            used += 3;
        }
        spans.push(Span::styled(key.to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint.to_string(), theme::muted()));
        used += pair.chars().count();
        placed += 1;
    }

    if overflow {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("help".to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled("more".to_string(), theme::muted()));
    }

    Line::from(spans)
}
