//! Depth-stack widgets. Every dense surface renders through `render_scroll_pane`
//! (budget-by-construction) or `stanza_lines` (bounded expansion), so clipping a
//! border is structurally impossible. `…⏎` is a promise: the full text is one
//! `z`/`Enter` away in record zoom.

use crate::app::{DrawerTab, FindingPane, WorkbenchDepth, WorkbenchNav};
use crate::renderer::shared::text::{fit_path, wrap_text};
use crate::theme;
use crate::ui_view_models::Stanza;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(super) const MORE: &str = "…⏎";

// ── focus + dominance chrome ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PaneRole {
    Rail,     // spine / drawer — light border
    Dominant, // data-flow ladder / record — double border, always accented
}

/// Triple-coded focus: border weight, hue, and an inverse-video title chip. The
/// dominant pane keeps a double border regardless of focus so it reads as the
/// focal surface even in monochrome (weight survives when hue cannot).
pub(super) fn pane_block(title: &str, focused: bool, role: PaneRole) -> Block<'static> {
    let border_type = match (role, focused) {
        (PaneRole::Dominant, _) => BorderType::Double,
        (PaneRole::Rail, true) => BorderType::Thick,
        (PaneRole::Rail, false) => BorderType::Plain,
    };
    let border_style = if focused {
        theme::accent()
    } else if role == PaneRole::Dominant {
        theme::label()
    } else {
        theme::subtle()
    };
    Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .title(title_chip(title, focused))
}

fn title_chip(title: &str, focused: bool) -> Span<'static> {
    if focused {
        Span::styled(format!("▌{title}▐"), theme::selection())
    } else {
        Span::styled(format!(" {title} "), theme::muted())
    }
}

/// The one scrollable-pane entry point. Budgets content to the block interior
/// and stamps the `↑N ↓N` overflow counter into the border, never into content.
pub(super) fn render_scroll_pane(
    frame: &mut Frame<'_>,
    area: Rect,
    block: Block<'static>,
    lines: Vec<Line<'static>>,
    scroll: &crate::app::BoundedScroll,
) {
    if area.width < 2 || area.height < 2 {
        return;
    }
    let inner = block.inner(area);
    let (above, below) = scroll.overflow(lines.len(), inner.height);
    // `title_top` honours the line's own alignment (a bare `.title(Line)` does
    // not), so the counter right-aligns instead of colliding with the title.
    let block = block.title_top(overflow_title(above, below));
    frame.render_widget(block, area);
    let offset = scroll.resolved(lines.len(), inner.height);
    let paragraph = Paragraph::new(lines)
        .scroll((offset, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

fn overflow_title(above: usize, below: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("↑{above} "), theme::subtle()),
        Span::styled(format!("↓{below}"), theme::subtle()),
    ])
    .alignment(Alignment::Right)
}

// ── stanza contract (bounded expansion) ─────────────────────────────────────

/// One record. Collapsed = a single line; expanded = header + ≤3 wrapped body
/// lines. Callers keep one stanza expanded per pane (accordion), so a pane's
/// height is `N collapsed + 1 expansion` — always boundable.
pub(super) fn stanza_lines(stanza: &Stanza, width: usize, expanded: bool) -> Vec<Line<'static>> {
    let mut lines = vec![stanza_head(stanza, expanded, width)];
    if expanded {
        for chunk in wrap_capped(&stanza.body, width.saturating_sub(2), 3) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(chunk, theme::muted()),
            ]));
        }
    }
    lines
}

fn stanza_head(stanza: &Stanza, expanded: bool, width: usize) -> Line<'static> {
    let marker = if expanded { "▼ " } else { "▶ " };
    let head = format!("{marker}{} ", stanza.id);
    let state = format!(" {} ", stanza.state);
    let used = cols(&head) + cols(&state) + 1;
    Line::from(vec![
        Span::styled(head, theme::muted()),
        Span::styled(state, theme::severity_tone(stanza.state_tone)),
        Span::raw(" "),
        Span::styled(
            elide(&stanza.summary, Elide::Prose, width.saturating_sub(used)),
            theme::primary(),
        ),
    ])
}

/// Wrap to at most `max` lines; the final line ends in `…⏎` when clipped.
fn wrap_capped(body: &str, width: usize, max: usize) -> Vec<String> {
    let mut lines = wrap_text(body, width);
    if lines.len() > max {
        lines.truncate(max);
        if let Some(last) = lines.last_mut() {
            *last = format!(
                "{}{MORE}",
                clip_cols(last, width.saturating_sub(cols(MORE)))
            );
        }
    }
    lines
}

// ── typed elision ───────────────────────────────────────────────────────────

pub(super) enum Elide {
    Id,    // middle-ellipsis: head+tail both identify (SQLI-0…14)
    Prose, // right + `…⏎`
    Path,  // reuse the repo's tail-keeping path fitter
}

pub(super) fn elide(value: &str, kind: Elide, width: usize) -> String {
    match kind {
        Elide::Id => elide_id(value, width),
        Elide::Prose => elide_prose(value, width),
        Elide::Path => fit_path(value, width),
    }
}

fn elide_prose(value: &str, width: usize) -> String {
    if cols(value) <= width {
        return value.to_string();
    }
    let budget = width.saturating_sub(cols(MORE));
    format!("{}{MORE}", clip_cols(value, budget))
}

fn elide_id(value: &str, width: usize) -> String {
    if cols(value) <= width || width < 3 {
        return clip_cols(value, width);
    }
    let keep = width - 1; // room for the middle '…'
    let head = keep.div_ceil(2);
    let tail = keep - head;
    format!("{}…{}", clip_cols(value, head), clip_tail(value, tail))
}

// ── log head-tail window + fan-out cap ──────────────────────────────────────

/// Newest and oldest lines survive; the bulk collapses to a counted
/// interstitial that names the hidden count and the key to open it.
pub(super) fn log_window(lines: &[String], budget: usize) -> Vec<String> {
    if budget == 0 || lines.len() <= budget {
        return lines.to_vec();
    }
    let head = 2.min(budget.saturating_sub(1));
    let tail = budget.saturating_sub(head + 1);
    let hidden = lines.len() - head - tail;
    let mut out = lines[..head].to_vec();
    out.push(format!("··· {hidden} lines · Enter to open ···"));
    out.extend_from_slice(&lines[lines.len() - tail..]);
    out
}

/// Cap any parent→child fan-out; returns the visible slice and the hidden count
/// for a cursorable `+N more` row.
pub(super) fn fan_out<T>(items: &[T], cap: usize) -> (&[T], usize) {
    let visible = items.len().min(cap);
    (&items[..visible], items.len().saturating_sub(cap))
}

// ── operations bar + key rail (self-contained rows below the body) ──────────

/// A single key-rail entry: `(key, label)`.
type KeyHint = (&'static str, &'static str);

/// Context-valid keys only, in fixed order motion → action → lateral → exit.
/// Invalid keys are omitted, never dimmed — a dimmed key still costs a read.
pub(super) fn key_hints(nav: &WorkbenchNav) -> Vec<KeyHint> {
    match nav.depth {
        WorkbenchDepth::List if nav.peek => {
            vec![("Space", "close"), ("Enter", "open"), ("j/k", "move")]
        }
        WorkbenchDepth::List => {
            vec![
                ("j/k", "move"),
                ("Space", "peek"),
                ("Enter", "open"),
                ("Esc", "leave"),
            ]
        }
        WorkbenchDepth::Finding => finding_hints(nav.pane),
        WorkbenchDepth::Record => {
            vec![
                ("j/k", "scroll"),
                ("g/G", "ends"),
                ("y", "yank"),
                ("Esc", "back"),
            ]
        }
    }
}

fn finding_hints(pane: FindingPane) -> Vec<KeyHint> {
    match pane {
        FindingPane::Spine => {
            vec![
                ("j/k", "walk"),
                ("Enter", "focus"),
                ("Tab", "pane"),
                ("Esc", "list"),
            ]
        }
        FindingPane::Ladder => vec![
            ("j/k", "step"),
            ("e", "expand"),
            ("Tab", "drawer"),
            ("J/K", "finding"),
            ("z", "zoom"),
            ("Esc", "back"),
        ],
        FindingPane::Drawer => {
            vec![
                ("j/k", "row"),
                ("[ ]", "tab"),
                ("Enter", "zoom"),
                ("Tab", "spine"),
                ("Esc", "back"),
            ]
        }
    }
}

pub(super) fn key_rail_line(nav: &WorkbenchNav) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    for (index, (key, label)) in key_hints(nav).into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" · ", theme::subtle()));
        }
        spans.push(Span::styled(key.to_string(), theme::accent()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(label.to_string(), theme::muted()));
    }
    Line::from(spans)
}

/// Row: `▌LADDER▐ step 3/5 · req→exec        spine·[LADDER]·drawer`.
pub(super) fn operations_bar_line(nav: &WorkbenchNav, echo: &str, width: usize) -> Line<'static> {
    let left = vec![
        title_chip(focus_label(nav), true),
        Span::raw(" "),
        Span::styled(echo.to_string(), theme::muted()),
    ];
    justify(left, focus_map(nav), width)
}

fn focus_label(nav: &WorkbenchNav) -> &'static str {
    match nav.depth {
        WorkbenchDepth::List => "FINDINGS",
        WorkbenchDepth::Finding => nav.pane.label(),
        WorkbenchDepth::Record => "ZOOM",
    }
}

fn focus_map(nav: &WorkbenchNav) -> Vec<Span<'static>> {
    let surfaces: &[(&str, bool)] = match nav.depth {
        WorkbenchDepth::List => &[("findings", true), ("peek", nav.peek)],
        WorkbenchDepth::Finding => &[
            ("spine", matches!(nav.pane, FindingPane::Spine)),
            ("ladder", matches!(nav.pane, FindingPane::Ladder)),
            ("drawer", matches!(nav.pane, FindingPane::Drawer)),
        ],
        WorkbenchDepth::Record => &[("finding", false), ("zoom", true)],
    };
    let mut spans = Vec::new();
    for (index, (name, focused)) in surfaces.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled("·", theme::subtle()));
        }
        spans.push(focus_map_span(name, *focused));
    }
    spans
}

fn focus_map_span(name: &str, focused: bool) -> Span<'static> {
    if focused {
        Span::styled(format!("[{}]", name.to_uppercase()), theme::accent())
    } else {
        Span::styled(name.to_string(), theme::subtle())
    }
}

fn justify(left: Vec<Span<'static>>, right: Vec<Span<'static>>, width: usize) -> Line<'static> {
    let used = span_cols(&left) + span_cols(&right);
    let gap = width.saturating_sub(used).max(1);
    let mut spans = left;
    spans.push(Span::raw(" ".repeat(gap)));
    spans.extend(right);
    Line::from(spans)
}

fn span_cols(spans: &[Span<'_>]) -> usize {
    spans.iter().map(|span| cols(span.content.as_ref())).sum()
}

// ── drawing-time column helpers (unicode-width, matching the text module) ───

pub(super) fn cols(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

pub(super) fn clip_cols(value: &str, width: usize) -> String {
    let mut used = 0usize;
    let mut out = String::new();
    for ch in value.chars() {
        let next = used + UnicodeWidthChar::width(ch).unwrap_or(0);
        if next > width {
            break;
        }
        out.push(ch);
        used = next;
    }
    out
}

fn clip_tail(value: &str, width: usize) -> String {
    let mut used = 0usize;
    let mut chars = Vec::new();
    for ch in value.chars().rev() {
        let next = used + UnicodeWidthChar::width(ch).unwrap_or(0);
        if next > width {
            break;
        }
        chars.push(ch);
        used = next;
    }
    chars.into_iter().rev().collect()
}
