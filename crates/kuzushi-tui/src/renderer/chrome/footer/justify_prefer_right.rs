use super::*;
use crate::ui_view_models::footer_keybindings;

mod dfd_navigation;
mod replay_navigation;

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
    let compact = crate::ui_view_models::compact_replay_reading(app, frame.area().height);
    let separator = area.height > 1 && !compact;
    let mut lines = Vec::new();
    if separator {
        lines.push(Line::styled(
            theme::RULE_CHAR.repeat(area.width as usize),
            theme::subtle(),
        ));
    }
    let key_rows = area.height - u16::from(separator);
    lines.extend(keybinding_rows(app, area.width as usize, key_rows));
    render_lines(frame, area, lines);
}

fn keybinding_rows(app: &ShellApp, width: usize, rows: u16) -> Vec<Line<'static>> {
    if rows < 2 {
        return vec![keybindings_line(app, width)];
    }
    let (top, bottom) = split_keybindings_for_wrap(app);
    let (top, overflow) = keybindings_line_for_wrapped_row(top, width, OverflowHint::Defer);
    let (bottom, _) =
        keybindings_line_for_wrapped_row(bottom, width, OverflowHint::ShowIf(overflow));
    vec![top, bottom]
}

fn split_keybindings_for_wrap(app: &ShellApp) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut bindings: Vec<(String, String)> = footer_keybindings(app)
        .into_iter()
        .map(|binding| (binding.key, binding.label))
        .collect();
    if review_navigation_applies(app, &bindings) {
        return review_navigation_rows(bindings);
    }
    if dfd_navigation::has_findings_link(&bindings) {
        return dfd_navigation::rows(bindings);
    }
    if replay_navigation::applies(app, &bindings) {
        return replay_navigation::rows(bindings);
    }
    bindings = bindings.into_iter().map(compact_export_binding).collect();
    bindings.sort_by_key(|binding| wrapped_binding_priority((&binding.0, &binding.1)));
    distribute_wrapped_bindings(bindings)
}

fn review_navigation_applies(app: &ShellApp, bindings: &[(String, String)]) -> bool {
    crate::ui_view_models::review_queue_navigation_footer(app)
        && has_review_queue_bindings(bindings)
}

fn has_review_queue_bindings(bindings: &[(String, String)]) -> bool {
    if bindings
        .iter()
        .any(|(key, _)| matches!(key.as_str(), "Ctrl+N" | "Ctrl+P" | "Ctrl+N/P"))
    {
        return false;
    }
    ["End", "G"]
        .iter()
        .all(|expected| bindings.iter().any(|(key, _)| key == expected))
}

fn review_navigation_rows(
    bindings: Vec<(String, String)>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    const READER_KEYS: [&str; 3] = ["Esc", "Enter", "End"];
    let (mut reader, mut actions): (Vec<_>, Vec<_>) =
        bindings.into_iter().partition(|(key, label)| {
            is_linked_reader_return(label) || READER_KEYS.contains(&key.as_str())
        });
    reader.sort_by_key(|(key, label)| {
        if is_linked_reader_return(label) {
            return 0;
        }
        1 + READER_KEYS
            .iter()
            .position(|candidate| candidate == key)
            .unwrap_or(READER_KEYS.len())
    });
    let reader = reader.into_iter().map(compact_reader_binding).collect();
    actions.sort_by_key(|(key, _)| match key.as_str() {
        "Ctrl+F" => 0,
        "G" => 1,
        _ => 2,
    });
    (reader, actions)
}

fn is_linked_reader_return(label: &str) -> bool {
    matches!(label, "diagram" | "scopes")
}

fn compact_reader_binding((key, label): (String, String)) -> (String, String) {
    let label = match (key.as_str(), label.as_str()) {
        ("Enter", "export running") => "wait".to_string(),
        ("Enter", "open detail") => "detail".to_string(),
        _ => label,
    };
    (key, label)
}

fn compact_export_binding((key, label): (String, String)) -> (String, String) {
    let label = match (key.as_str(), label.as_str()) {
        ("Enter", "export/retry") => "export".to_string(),
        ("e", "edit path") => "path".to_string(),
        _ => label,
    };
    (key, label)
}

fn wrapped_binding_priority(binding: (&str, &str)) -> u8 {
    match binding {
        ("j/k", "select") | ("↑/↓", "action") | ("Ctrl+F", "filter") => 0,
        ("Ctrl+N" | "Ctrl+P" | "Ctrl+N/P", _) => 0,
        ("Ctrl+C" | "Ctrl+G" | "Ctrl+Y" | "Esc" | "Esc/q" | "q" | "PgUp/PgDn", _) => 0,
        ("Enter" | "Tab" | "Shift+Tab", _) | ("e", "path") => 1,
        (key, _) if looks_like_typed_command(key) => 3,
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
    let gap = if app.input_mode() == crate::InputMode::Navigate
        && crate::ui_view_models::workbench_prompt_mode(app)
            == Some(crate::app::WorkbenchPage::Review)
        && !app.has_running_work()
    {
        2
    } else {
        3
    };
    Line::from(keybinding_spans_with_spacing(bindings, width, OverflowHint::ShowIf(false), gap).0)
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
    keybinding_spans_with_spacing(bindings, width, hint, 3)
}

fn keybinding_spans_with_spacing<K: Into<String>, L: Into<String>>(
    bindings: Vec<(K, L)>,
    width: usize,
    hint: OverflowHint,
    gap: usize,
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
    let mut layout = KeybindingLineLayout::new(width, reserve, gap);
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
    gap: usize,
}

impl KeybindingLineLayout {
    fn new(width: usize, reserve: usize, gap: usize) -> Self {
        Self {
            overflow: false,
            placed: 0,
            reserve,
            used: 1,
            width,
            gap,
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
            self.gap
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
            spans.push(Span::raw(" ".repeat(self.gap)));
            self.used += self.gap;
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
    #[test]
    fn compact_paste_footer_keeps_inspection_clear_undo_and_interrupt_visible() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = crate::ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_shell_view(crate::ShellView::Workbench);
        app.set_input_mode(crate::InputMode::Prompt);
        app.editor_mut()
            .insert_multiline_paste("first α\nsecond β\n");
        for active in [false, true] {
            if active {
                app.set_running_tool_for_test("context:build");
            }
            let mut terminal = Terminal::new(TestBackend::new(40, 3)).unwrap();
            terminal
                .draw(|frame| super::render_keybind_footer(frame, Rect::new(0, 0, 40, 3), &app))
                .unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect::<String>();
            for control in [
                "Ctrl+Y", "inspect", "Esc", "clear", "Ctrl+_", "undo", "Ctrl+C",
            ] {
                assert!(
                    text.contains(control),
                    "{active}: missing {control}: {text}"
                );
            }
        }
    }

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

    #[test]
    fn wrapped_footer_keeps_prioritized_reader_paging_at_40_columns() {
        let mut bindings = vec![
            ("PgUp/PgDn", "scroll"),
            ("Esc", "prompt"),
            ("Ctrl+G", "palette"),
            ("q", "review list"),
            ("Tab", "pane"),
        ];
        bindings.sort_by_key(|binding| wrapped_binding_priority(*binding));
        let (top, bottom) = distribute_wrapped_bindings(bindings);
        let (top, overflow) = keybindings_line_for_wrapped_row(top, 40, OverflowHint::Defer);
        let (bottom, _) =
            keybindings_line_for_wrapped_row(bottom, 40, OverflowHint::ShowIf(overflow));
        let text = [line_text(&top), line_text(&bottom)].join("\n");
        assert!(text.contains("PgUp/PgDn scroll"), "{text}");
        assert!(text.contains("Esc prompt"), "{text}");
    }

    #[test]
    fn compact_review_keeps_the_diagram_return_visible_with_its_actual_key() {
        for key in ["q", "Ctrl+B"] {
            let bindings = [
                ("Esc", "prompt"),
                ("Enter", "detail"),
                ("End", "last"),
                ("Ctrl+F", "filter"),
                ("G", "groups"),
                (key, "diagram"),
            ]
            .into_iter()
            .map(|(key, label)| (key.into(), label.into()))
            .collect();
            let (top, bottom) = review_navigation_rows(bindings);
            let (top, overflow) = keybindings_line_for_wrapped_row(top, 40, OverflowHint::Defer);
            let (bottom, _) =
                keybindings_line_for_wrapped_row(bottom, 40, OverflowHint::ShowIf(overflow));
            let text = [line_text(&top), line_text(&bottom)].join("\n");
            assert!(text.contains(&format!("{key} diagram")), "{text}");
            assert!(
                text.contains("Esc prompt") && text.contains("Ctrl+F filter"),
                "{text}"
            );
        }
    }

    #[test]
    fn compact_review_prioritizes_scope_return_without_losing_filter_or_input_owner() {
        let bindings = [
            ("Esc", "prompt"),
            ("Enter", "detail"),
            ("End", "last"),
            ("Ctrl+F", "filter"),
            ("G", "groups"),
            ("q", "scopes"),
        ]
        .into_iter()
        .map(|(key, label)| (key.into(), label.into()))
        .collect();
        let (top, bottom) = review_navigation_rows(bindings);
        let (top, overflow) = keybindings_line_for_wrapped_row(top, 40, OverflowHint::Defer);
        let (bottom, _) =
            keybindings_line_for_wrapped_row(bottom, 40, OverflowHint::ShowIf(overflow));
        let text = [line_text(&top), line_text(&bottom)].join("\n");
        for expected in ["q scopes", "Esc prompt", "Ctrl+F filter"] {
            assert!(text.contains(expected), "{text}");
        }
    }

    #[test]
    fn wrapped_footer_keeps_global_ledger_filter_at_40_columns() {
        let mut bindings = vec![
            ("Esc", "prompt"),
            ("Ctrl+F", "filter"),
            ("Ctrl+C", "exit"),
            ("r", "Report"),
            ("Ctrl+G", "palette"),
            ("Tab", "pane"),
        ];
        bindings.sort_by_key(|binding| wrapped_binding_priority(*binding));
        let (top, bottom) = distribute_wrapped_bindings(bindings);
        let (top, overflow) = keybindings_line_for_wrapped_row(top, 40, OverflowHint::Defer);
        let (bottom, _) =
            keybindings_line_for_wrapped_row(bottom, 40, OverflowHint::ShowIf(overflow));
        let text = [line_text(&top), line_text(&bottom)].join("\n");
        assert!(text.contains("Ctrl+F filter"), "{text}");
        assert!(text.contains("Esc prompt"), "{text}");
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
