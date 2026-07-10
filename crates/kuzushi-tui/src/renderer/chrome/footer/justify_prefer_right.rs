use super::*;
use crate::ui_view_models::footer_keybindings;

pub(crate) fn justify_prefer_right(left: String, right: String, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if right.is_empty() {
        return fit(&left, width);
    }
    let right = fit(&right, width);
    let right_len = display_width(&right);
    if right_len + 1 >= width {
        return right;
    }
    let left_budget = width.saturating_sub(right_len + 1);
    let left = fit(&left, left_budget);
    let left_len = display_width(&left);
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

    // M4 §4.2: when the area is tall enough for two keybinding rows
    // (`keybind_footer_height` returns 3 on narrow widths), wrap the
    // binding list across both lines so nothing truncates. Otherwise
    // keep the single-line layout that the wide-terminal snapshot has
    // pinned for years.
    if area.height >= 3 {
        let (top, bottom) = split_keybindings_for_wrap(app);
        lines.push(keybindings_line_from_pairs(top, area.width as usize));
        lines.push(keybindings_line_from_pairs(bottom, area.width as usize));
    } else if area.height > 1 {
        lines.push(keybindings_line(app, area.width as usize));
    }

    render_lines(frame, area, lines);
}

fn split_keybindings_for_wrap(
    app: &ShellApp,
) -> (
    Vec<(&'static str, &'static str)>,
    Vec<(&'static str, &'static str)>,
) {
    let bindings: Vec<(&'static str, &'static str)> = footer_keybindings(app)
        .into_iter()
        .map(|binding| (binding.key, binding.label))
        .collect();
    let midpoint = bindings.len().div_ceil(2);
    let (top, bottom) = bindings.split_at(midpoint);
    (top.to_vec(), bottom.to_vec())
}

fn keybindings_line_from_pairs(
    bindings: Vec<(&'static str, &'static str)>,
    width: usize,
) -> Line<'static> {
    Line::from(keybinding_spans(bindings, width))
}

pub(crate) fn keybindings_line(app: &ShellApp, width: usize) -> Line<'static> {
    let bindings = footer_keybindings(app)
        .into_iter()
        .map(|binding| (binding.key, binding.label))
        .collect();
    Line::from(keybinding_spans(bindings, width))
}

fn keybinding_spans(
    bindings: Vec<(&'static str, &'static str)>,
    width: usize,
) -> Vec<Span<'static>> {
    const TAIL: &str = "help more";
    let reserve = 3 + TAIL.chars().count();
    let bindings_len = bindings.len();
    let mut layout = KeybindingLineLayout::new(width, reserve);
    let mut spans = vec![Span::raw(" ")];

    for (i, binding) in bindings.into_iter().enumerate() {
        if !layout.try_push(&mut spans, binding, i + 1 == bindings_len) {
            break;
        }
    }
    append_overflow_hint(&mut spans, layout.overflow);
    spans
}

fn append_overflow_hint(spans: &mut Vec<Span<'static>>, overflow: bool) {
    if overflow {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("help".to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled("more".to_string(), theme::muted()));
    }
}

struct KeybindingLineLayout {
    overflow: bool,
    placed: usize,
    reserve: usize,
    used: usize,
    width: usize,
}

impl KeybindingLineLayout {
    fn new(width: usize, reserve: usize) -> Self {
        Self {
            overflow: false,
            placed: 0,
            reserve,
            used: 1,
            width,
        }
    }

    fn try_push(
        &mut self,
        spans: &mut Vec<Span<'static>>,
        binding: (&'static str, &'static str),
        is_last: bool,
    ) -> bool {
        let pair_len = pair_len(binding);
        let need = self.separator_len() + pair_len;
        if self.used + need > self.capacity(is_last) && self.placed > 0 {
            self.overflow = true;
            return false;
        }
        self.push_separator(spans);
        push_binding_pair(spans, binding);
        self.used += pair_len;
        self.placed += 1;
        true
    }

    fn separator_len(&self) -> usize {
        if self.placed == 0 {
            0
        } else {
            3
        }
    }

    fn capacity(&self, is_last: bool) -> usize {
        if is_last {
            self.width.saturating_sub(1)
        } else {
            self.width.saturating_sub(self.reserve + 1)
        }
    }

    fn push_separator(&mut self, spans: &mut Vec<Span<'static>>) {
        if self.placed > 0 {
            spans.push(Span::raw("   "));
            self.used += 3;
        }
    }
}

fn pair_len((key, label): (&str, &str)) -> usize {
    key.chars().count() + 1 + label.chars().count()
}

fn push_binding_pair(spans: &mut Vec<Span<'static>>, (key, label): (&'static str, &'static str)) {
    spans.push(Span::styled(key.to_string(), binding_key_style(key)));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(label.to_string(), theme::muted()));
}

fn binding_key_style(key: &str) -> ratatui::style::Style {
    if looks_like_typed_command(key) {
        theme::warn()
    } else {
        theme::accent()
    }
}

fn looks_like_typed_command(key: &str) -> bool {
    !looks_like_physical_key(key)
        && key
            .chars()
            .any(|ch| ch.is_ascii_alphabetic() && ch.is_ascii_lowercase())
        && key.chars().count() > 1
}

fn looks_like_physical_key(key: &str) -> bool {
    key.chars().count() == 1
        || key.contains('/')
        || key.contains('+')
        || matches!(
            key,
            "Tab"
                | "Shift+Tab"
                | "Enter"
                | "Esc"
                | "Space"
                | "Backspace"
                | "PgUp"
                | "PgDn"
                | "PgUp/PgDn"
                | "Up"
                | "Down"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_atom_survives_double_width_left_labels() {
        let line = justify_prefer_right(
            "mode:shell · 組 map 1/4 · ⛭ 掛 fix · workbench".to_string(),
            "7 findings".to_string(),
            60,
        );

        assert_eq!(display_width(&line), 60);
        assert!(line.ends_with("7 findings"), "{line}");
    }
}
