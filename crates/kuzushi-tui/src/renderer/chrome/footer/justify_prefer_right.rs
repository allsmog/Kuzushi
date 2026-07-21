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
        let (top, top_overflow) =
            keybindings_line_for_wrapped_row(top, area.width as usize, OverflowHint::Defer);
        let (bottom, _) = keybindings_line_for_wrapped_row(
            bottom,
            area.width as usize,
            OverflowHint::ShowIf(top_overflow),
        );
        lines.push(top);
        lines.push(bottom);
    } else if area.height > 1 {
        lines.push(keybindings_line(app, area.width as usize));
    }

    render_lines(frame, area, lines);
}

fn split_keybindings_for_wrap(app: &ShellApp) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut bindings: Vec<(String, String)> = footer_keybindings(app)
        .into_iter()
        .map(|binding| (binding.key, binding.label))
        .collect();
    bindings.sort_by_key(|binding| wrapped_binding_priority((&binding.0, &binding.1)));
    distribute_wrapped_bindings(bindings)
}

fn wrapped_binding_priority(binding: (&str, &str)) -> u8 {
    match binding.0 {
        "Ctrl+C" | "Ctrl+G" | "Esc" | "Esc/q" | "q" => 0,
        "Enter" | "PgUp/PgDn" | "Tab" | "Shift+Tab" => 1,
        key if looks_like_typed_command(key) => 3,
        _ => 2,
    }
}

fn distribute_wrapped_bindings<K: Into<String>, L: Into<String>>(
    bindings: Vec<(K, L)>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut rows = [Vec::new(), Vec::new()];
    let mut widths = [0usize, 0usize];
    for (key, label) in bindings {
        let binding = (key.into(), label.into());
        let row = usize::from(widths[1] < widths[0]);
        widths[row] += pair_len((&binding.0, &binding.1)) + usize::from(!rows[row].is_empty()) * 3;
        rows[row].push(binding);
    }
    let [top, bottom] = rows;
    (top, bottom)
}

fn keybindings_line_for_wrapped_row<K: Into<String>, L: Into<String>>(
    bindings: Vec<(K, L)>,
    width: usize,
    hint: OverflowHint,
) -> (Line<'static>, bool) {
    let (spans, overflow) = keybinding_spans_with_hint(bindings, width, hint);
    (Line::from(spans), overflow)
}

pub(crate) fn keybindings_line(app: &ShellApp, width: usize) -> Line<'static> {
    let bindings = footer_keybindings(app)
        .into_iter()
        .map(|binding| (binding.key, binding.label))
        .collect();
    Line::from(keybinding_spans_with_hint(bindings, width, OverflowHint::ShowIf(false)).0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverflowHint {
    Defer,
    ShowIf(bool),
}

fn keybinding_spans_with_hint<K: Into<String>, L: Into<String>>(
    bindings: Vec<(K, L)>,
    width: usize,
    hint: OverflowHint,
) -> (Vec<Span<'static>>, bool) {
    const TAIL: &str = "/keys all";
    let inherited_overflow = matches!(hint, OverflowHint::ShowIf(true));
    let reserve = match hint {
        OverflowHint::Defer => 0,
        OverflowHint::ShowIf(_) => 3 + TAIL.chars().count(),
    };
    let bindings = bindings
        .into_iter()
        .map(|(key, label)| (key.into(), label.into()))
        .collect::<Vec<_>>();
    let bindings_len = bindings.len();
    let mut layout = KeybindingLineLayout::new(width, reserve);
    let mut spans = vec![Span::raw(" ")];

    for (i, binding) in bindings.into_iter().enumerate() {
        let is_last_without_inherited_overflow =
            i + 1 == bindings_len && !inherited_overflow && !layout.overflow;
        layout.try_push(&mut spans, binding, is_last_without_inherited_overflow);
    }
    let overflow = inherited_overflow || layout.overflow;
    append_overflow_hint(&mut spans, overflow && hint != OverflowHint::Defer);
    (spans, overflow)
}

fn append_overflow_hint(spans: &mut Vec<Span<'static>>, overflow: bool) {
    if overflow {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("/keys".to_string(), theme::warn()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled("all".to_string(), theme::muted()));
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
        binding: (String, String),
        is_last: bool,
    ) -> bool {
        let pair_len = pair_len((&binding.0, &binding.1));
        let need = self.separator_len() + pair_len;
        if self.used + need > self.capacity(is_last) {
            self.overflow = true;
            if self.placed > 0 {
                return false;
            }
            let available = self.capacity(is_last).saturating_sub(self.used);
            push_fitted_binding_pair(spans, (&binding.0, &binding.1), available);
            self.used += available;
            self.placed += usize::from(available > 0);
            return false;
        }
        self.push_separator(spans);
        push_binding_pair(spans, (&binding.0, &binding.1));
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
    display_width(key) + 1 + display_width(label)
}

fn push_binding_pair(spans: &mut Vec<Span<'static>>, (key, label): (&str, &str)) {
    spans.push(Span::styled(key.to_string(), binding_key_style(key)));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(label.to_string(), theme::muted()));
}

fn push_fitted_binding_pair(
    spans: &mut Vec<Span<'static>>,
    (key, label): (&str, &str),
    width: usize,
) {
    if width == 0 {
        return;
    }
    let key_width = display_width(key);
    if key_width + 1 >= width {
        spans.push(Span::styled(fit(key, width), binding_key_style(key)));
        return;
    }
    spans.push(Span::styled(key.to_string(), binding_key_style(key)));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        fit(label, width.saturating_sub(key_width + 1)),
        theme::muted(),
    ));
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
            "route:shell · 組 map 1/5 · ⛭ 掛 fix · workbench".to_string(),
            "7 findings".to_string(),
            60,
        );

        assert_eq!(display_width(&line), 60);
        assert!(line.ends_with("7 findings"), "{line}");
    }

    #[test]
    fn wrapped_footer_emits_one_overflow_pointer_for_both_rows() {
        let (top, top_overflow) = keybindings_line_for_wrapped_row(
            vec![
                ("Ctrl+C", "request abort"),
                ("findings", "list"),
                ("Esc", "prompt"),
            ],
            30,
            OverflowHint::Defer,
        );
        let (bottom, bottom_overflow) = keybindings_line_for_wrapped_row(
            vec![("1..5", "page"), ("Tab", "pane"), ("j/k/↑/↓", "move")],
            30,
            OverflowHint::ShowIf(top_overflow),
        );
        let rendered = [line_text(&top), line_text(&bottom)].join("\n");

        assert!(top_overflow);
        assert!(bottom_overflow);
        assert_eq!(rendered.matches("/keys all").count(), 1, "{rendered}");
    }

    #[test]
    fn oversized_first_binding_never_clips_the_overflow_pointer() {
        let (line, overflow) = keybindings_line_for_wrapped_row(
            vec![("findings export report.sarif sarif", "export report")],
            30,
            OverflowHint::ShowIf(true),
        );
        let rendered = line_text(&line);

        assert!(overflow);
        assert!(display_width(&rendered) <= 30, "{rendered}");
        assert!(rendered.ends_with("/keys all"), "{rendered}");
    }

    #[test]
    fn oversized_middle_binding_does_not_hide_later_exit_control() {
        let (spans, overflow) = keybinding_spans_with_hint(
            vec![
                ("Enter", "open"),
                ("run sast:scan {}", "rescan now"),
                ("Ctrl+C", "exit"),
            ],
            40,
            OverflowHint::ShowIf(false),
        );
        let rendered = spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(overflow);
        assert!(rendered.contains("Ctrl+C"), "{rendered}");
        assert!(rendered.ends_with("/keys all"), "{rendered}");
    }

    #[test]
    fn wrapped_distribution_prioritizes_lifecycle_controls_by_rendered_width() {
        let mut bindings = vec![
            ("run sast:scan {}", "rescan now"),
            ("Ctrl+C", "exit"),
            ("Ctrl+G", "palette"),
            ("Esc", "prompt"),
            ("PgUp/PgDn", "scroll"),
        ];
        bindings.sort_by_key(|binding| wrapped_binding_priority(*binding));
        let (top, bottom) = distribute_wrapped_bindings(bindings);
        let (top, top_overflow) = keybindings_line_for_wrapped_row(top, 30, OverflowHint::Defer);
        let (bottom, _) =
            keybindings_line_for_wrapped_row(bottom, 30, OverflowHint::ShowIf(top_overflow));
        let rendered = [line_text(&top), line_text(&bottom)].join("\n");

        for key in ["Ctrl+C", "Ctrl+G", "Esc"] {
            assert!(rendered.contains(key), "missing {key}: {rendered}");
        }
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
