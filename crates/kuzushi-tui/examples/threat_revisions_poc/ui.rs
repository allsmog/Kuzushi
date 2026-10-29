//! Rendering. One tab bar, an optional one-line banner, the body, and one
//! status line — nothing else competes for attention.

use crate::app::{headline, App, ModelView, Tab, TABS};
use crate::chat::{Msg, Proposal};
use crate::md;
use crate::store::{age, short, truncate};
use kuzushi_core::capabilities::diff_threat_model_documents;
use kuzushi_tui::poc_map_gallery::{markdown_lines, render_map_gallery, MapGalleryPage};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use ratatui::Frame;
use std::path::Path;

fn accent() -> Style {
    Style::default().fg(Color::Cyan)
}
fn muted() -> Style {
    Style::default().fg(Color::DarkGray)
}
fn warn() -> Style {
    Style::default().fg(Color::Yellow)
}
fn good() -> Style {
    Style::default().fg(Color::Green)
}
fn bad() -> Style {
    Style::default().fg(Color::Red)
}
fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub fn draw(f: &mut Frame, app: &App) {
    let banner = banner(app);
    let [top, banner_area, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(u16::from(banner.is_some())),
        Constraint::Min(4),
        Constraint::Length(1),
    ])
    .areas(f.area());
    draw_tabs(f, app, top);
    if let Some(line) = banner {
        f.render_widget(Paragraph::new(line), banner_area);
    }
    let body = pad(body, 1, 1);
    match app.tab {
        Tab::Summary | Tab::Dfd => draw_map(f, app, body),
        Tab::Model => draw_model(f, app, body),
        Tab::Chat => draw_chat(f, app, body),
        Tab::History => draw_history(f, app, body),
    }
    draw_status(f, app, status);
    if app.confirm_restore.is_some() {
        draw_confirm(f, app);
    }
    if app.help {
        draw_help(f);
    }
}

fn pad(area: Rect, x: u16, y: u16) -> Rect {
    Rect { x: area.x + x, y: area.y + y.min(area.height), width: area.width.saturating_sub(2 * x), height: area.height.saturating_sub(y) }
}

/// Tabs on the left; the model label on the right only when it fits.
fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    for (i, tab) in TABS.iter().enumerate() {
        if *tab == app.tab {
            spans.push(Span::styled(format!(" {} ", tab.title()), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)));
        } else {
            spans.push(Span::styled(format!(" {}", i + 1), muted()));
            spans.push(Span::raw(format!(" {} ", tab.title())));
        }
        spans.push(Span::raw(" "));
    }
    let used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    let label = app
        .store
        .active
        .as_ref()
        .map(|a| {
            let l = &app.store.lineages[a.lineage];
            format!("{} · {} {} · {} ", app.system_name(), l.label, app.store.vlabel(a), l.methodology)
        })
        .unwrap_or_default();
    let width = label.chars().count() as u16;
    if used as u16 + width + 4 <= area.width {
        let right = Rect { x: area.right() - width, width, ..area };
        f.render_widget(Paragraph::new(Span::styled(label, muted())), right);
    }
}

fn banner(app: &App) -> Option<Line<'static>> {
    if let Some(card) = &app.card {
        let delta = card
            .pre_active
            .as_ref()
            .and_then(|p| app.store.rev(p))
            .zip(app.store.rev(&card.produced))
            .map(|(a, b)| headline(&diff_threat_model_documents(&a.document, &b.document)))
            .unwrap_or_default();
        let hint = if app.tab == Tab::Chat { "   /review · /keep · /regen [feedback] · /discard" } else { "   v review · u keep · g regen · x discard" };
        let attempt = card.recipe.as_ref().filter(|r| r.attempt > 1).map(|r| format!(" (attempt {})", r.attempt)).unwrap_or_default();
        return Some(Line::from(vec![
            Span::styled(format!(" ● {} {}{attempt} ", card.derivation, app.store.vlabel(&card.produced)), good().add_modifier(Modifier::BOLD)),
            Span::raw(delta),
            Span::styled(hint, muted()),
        ]));
    }
    if app.stale {
        return Some(Line::from(vec![Span::styled(" ⚠ model is stale vs the current commit", warn()), Span::styled("   Enter refine", muted())]));
    }
    None
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Summary | Tab::Dfd => "j/k select · e edit in vim · ? keys",
        Tab::Model => "r raw · d diff · e edit in vim · j/k scroll · ? keys",
        Tab::Chat if app.busy.is_some() => "esc interrupt",
        Tab::Chat => "enter send · /refine · drop files · ↑ scroll",
        Tab::History => "enter open · a activate · R restore · ? keys",
    };
    let [left, right] = Layout::horizontal([Constraint::Min(10), Constraint::Length(hints.chars().count() as u16 + 1)]).spacing(3).areas(area);
    f.render_widget(Paragraph::new(Span::styled(format!(" {}", app.status), muted())), left);
    f.render_widget(Paragraph::new(Span::styled(hints, muted())), right);
}

// ─────────────────────────── Summary / DFD ───────────────────────────

fn draw_map(f: &mut Frame, app: &App, area: Rect) {
    let (page, sel) = if app.tab == Tab::Dfd { (MapGalleryPage::Dfd, app.dfd_sel) } else { (MapGalleryPage::Summary, app.summary_sel) };
    let doc = app.store.active.as_ref().and_then(|a| app.store.rev(a)).map(|r| &r.document);
    render_map_gallery(page, doc, Some(Path::new(&app.store.target)), sel, area, f.buffer_mut());
}

// ──────────────────────────── Model ────────────────────────────

fn draw_model(f: &mut Frame, app: &App, area: Rect) {
    let Some(shown) = app.shown() else { return };
    let Some(rev) = app.store.rev(&shown) else { return };
    let [head, body] = Layout::vertical([Constraint::Length(2), Constraint::Min(3)]).areas(area);
    let view = |label: &'static str, v: ModelView| if app.model_view == v { Span::styled(label, bold().fg(Color::Cyan)) } else { Span::styled(label, muted()) };
    let state = if app.is_active(&shown) { Span::styled("active", good()) } else { Span::styled("not active · a activate · esc back", warn()) };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("THREAT_MODEL.md  ", bold()),
            Span::styled(format!("{} · {} · {}  ", app.store.vlabel(&shown), rev.source, age(rev.created_at)), muted()),
            state,
            Span::raw("    "),
            view("rendered", ModelView::Rendered),
            Span::styled(" · ", muted()),
            view("raw", ModelView::Raw),
            Span::styled(" · ", muted()),
            view("diff", ModelView::Diff),
        ])),
        head,
    );
    let lines = match app.model_view {
        ModelView::Rendered => markdown_lines(&app.md_for(rev), body.width as usize),
        ModelView::Raw => raw_lines(&app.md_for(rev)),
        ModelView::Diff => diff_lines(app, rev),
    };
    let scroll = app.model_scroll.min((lines.len() as u16).saturating_sub(body.height));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)), body);
}

fn raw_lines(text: &str) -> Vec<Line<'static>> {
    text.lines()
        .enumerate()
        .map(|(i, l)| {
            let style = if l.starts_with('#') { bold().fg(Color::Cyan) } else if l.starts_with("|---") { muted() } else { Style::default() };
            Line::from(vec![Span::styled(format!("{:>4}  ", i + 1), muted()), Span::styled(l.to_string(), style)])
        })
        .collect()
}

fn diff_lines(app: &App, rev: &crate::store::Rev) -> Vec<Line<'static>> {
    let Some(base_ref) = app.diff_baseline() else {
        return vec![Line::styled("first version — nothing to compare against", muted())];
    };
    let Some(base) = app.store.rev(&base_ref) else { return Vec::new() };
    let structural = diff_threat_model_documents(&base.document, &rev.document);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{} → {}  ", app.store.vlabel(&base_ref), app.shown().map(|s| app.store.vlabel(&s)).unwrap_or_default()), muted()),
        Span::styled(headline(&structural), accent()),
    ])];
    lines.extend(md::section_diff_lines(&app.md_for(base), &app.md_for(rev)));
    lines
}

// ──────────────────────────── Chat ─────────────────────────────

const SPINNER: [&str; 6] = ["✢", "✳", "✶", "✻", "✽", "✻"];

fn transcript_lines(app: &App, width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    if app.chat.is_empty() {
        lines.push(Line::styled(format!("Ask about {}'s threat model, or tell it what changed.", app.system_name()), muted()));
        lines.push(Line::styled("The model can read the repository and any files you drop here.", muted()));
        lines.push(Line::raw(""));
    }
    for msg in &app.chat {
        match msg {
            Msg::User(text) => {
                for (i, l) in text.lines().enumerate() {
                    let lead = if i == 0 { "> " } else { "  " };
                    lines.push(Line::styled(format!("{lead}{l}"), muted().add_modifier(Modifier::BOLD)));
                }
                lines.push(Line::raw(""));
            }
            Msg::Assistant(text) => {
                for (i, l) in markdown_lines(text, width.saturating_sub(2)).into_iter().enumerate() {
                    let lead = if i == 0 { Span::styled("⏺ ", Style::default().fg(Color::White)) } else { Span::raw("  ") };
                    let mut spans = vec![lead];
                    spans.extend(l.spans);
                    lines.push(Line::from(spans));
                }
                lines.push(Line::raw(""));
            }
            Msg::Tool(call) => lines.push(Line::from(vec![Span::styled("⏺ ", good()), Span::styled(call.clone(), bold())])),
            Msg::Event(text) => {
                let text = text.trim_start();
                let text = text.strip_prefix("⎿").map(str::trim_start).unwrap_or(text);
                lines.push(Line::styled(format!("  ⎿  {text}"), muted()));
            }
            Msg::Error(text) => lines.push(Line::styled(format!("  ⎿  {text}"), bad())),
        }
    }
    if let Some(busy) = &app.busy {
        let secs = busy.since.elapsed().as_secs();
        let glyph = SPINNER[(busy.since.elapsed().as_millis() / 150) as usize % SPINNER.len()];
        lines.push(Line::from(vec![
            Span::styled(format!("{glyph} {}… ", busy.label), warn()),
            Span::styled(format!("({secs}s · esc to interrupt)"), muted()),
        ]));
    }
    lines
}

fn draw_chat(f: &mut Frame, app: &App, area: Rect) {
    let composer_h = 3 + app.attachments.len() as u16;
    let pending_h = if app.pending.is_some() { 7 } else { 0 };
    let [transcript, pending, composer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(pending_h), Constraint::Length(composer_h)]).areas(area);
    let lines = transcript_lines(app, transcript.width as usize);
    let rendered = Paragraph::new(lines).wrap(Wrap { trim: false });
    let total = rendered.line_count(transcript.width) as u16;
    let scroll = total.saturating_sub(transcript.height).saturating_sub(app.chat_scroll);
    f.render_widget(rendered.scroll((scroll, 0)), transcript);

    if let Some(p) = &app.pending {
        let (title, detail) = match p {
            Proposal::Refine { seed } => ("Refine the threat model with this?".to_string(), format!("seed: {}", truncate(seed, 160))),
            Proposal::UpdateThreats { summary, updates } => (format!("Apply edit to {} threat(s)?", updates.len()), summary.clone()),
        };
        let text = vec![
            Line::styled(title, bold()),
            Line::styled(detail, muted()),
            Line::from(vec![Span::styled("❯ Enter ", accent()), Span::raw("yes    "), Span::styled("Esc ", accent()), Span::raw("no")]),
        ];
        f.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: true }).block(Block::bordered().border_type(BorderType::Rounded).border_style(warn())),
            pending,
        );
    }

    let mut body = Vec::new();
    for p in &app.attachments {
        let full = p.display().to_string();
        body.push(Line::from(vec![
            Span::styled(format!("📎 {}", crate::store::file_name(&full)), warn()),
            Span::styled(format!("  {}", p.parent().map(|d| d.display().to_string()).unwrap_or_default()), muted()),
        ]));
    }
    let prompt = if app.composer.is_empty() {
        Span::styled("Ask about the threat model, or tell it what changed…", muted())
    } else {
        Span::raw(app.composer.clone())
    };
    body.push(Line::from(vec![Span::styled("> ", accent()), prompt]));
    f.render_widget(Paragraph::new(body).block(Block::bordered().border_type(BorderType::Rounded).border_style(muted())), composer);
    let cx = composer.x + 3 + app.composer.chars().count() as u16;
    let cy = composer.y + 1 + app.attachments.len() as u16;
    if app.pending.is_none() && cx < composer.right().saturating_sub(1) {
        f.set_cursor_position(Position { x: cx, y: cy });
    }
}

// ─────────────────────────── History ───────────────────────────

fn draw_history(f: &mut Frame, app: &App, area: Rect) {
    let [list, _gap, detail] = Layout::horizontal([Constraint::Length(54), Constraint::Length(2), Constraint::Min(20)]).areas(area);
    let rows = app.history_rows();
    let mut lines = Vec::new();
    let mut last_lineage = None;
    let mut selected_line = 0;
    for (i, r) in rows.iter().enumerate() {
        if last_lineage != Some(r.lineage) {
            if last_lineage.is_some() {
                lines.push(Line::raw(""));
            }
            let l = &app.store.lineages[r.lineage];
            lines.push(Line::from(vec![Span::styled(format!("{} · {}", l.label, l.methodology), bold()), Span::styled(format!("  scope {}", l.scope), muted())]));
            last_lineage = Some(r.lineage);
        }
        let Some(rev) = app.store.rev(r) else { continue };
        let active = app.is_active(r);
        let verif = if rev.simulated { "new".to_string() } else { rev.verification.clone().unwrap_or_default() };
        let text = format!(
            " {} {:<4}{:<13}{:>8}  {:>2} threats  {}",
            if active { "●" } else { " " },
            app.store.vlabel(r),
            rev.source,
            age(rev.created_at),
            rev.document.get("threats").and_then(|t| t.as_array()).map_or(0, |a| a.len()),
            verif
        );
        let mut style = if active { good() } else { Style::default() };
        if i == app.hist_sel {
            style = style.add_modifier(Modifier::REVERSED);
            selected_line = lines.len();
        }
        lines.push(Line::styled(text, style));
    }
    let scroll = (selected_line as u16).saturating_sub(list.height.saturating_sub(2));
    f.render_widget(Paragraph::new(lines).scroll((scroll, 0)), list);

    let Some(sel) = rows.get(app.hist_sel) else { return };
    let Some(rev) = app.store.rev(sel) else { return };
    let mut detail_lines = vec![
        Line::from(vec![
            Span::styled(format!("{} ", app.store.label(sel)), bold()),
            Span::styled(format!("{} · {}", rev.source, short(&rev.sha)), muted()),
        ]),
        Line::raw(""),
    ];
    match app.store.previous(sel).and_then(|p| app.store.rev(&p).map(|r| (p, r))) {
        Some((p, prev)) => {
            let d = diff_threat_model_documents(&prev.document, &rev.document);
            detail_lines.push(Line::from(vec![Span::styled(format!("vs {}  ", app.store.vlabel(&p)), muted()), Span::styled(headline(&d), accent())]));
            detail_lines.extend(md::section_diff_lines(&app.md_for(prev), &app.md_for(rev)));
        }
        None => detail_lines.push(Line::styled("first version of this lineage", muted())),
    }
    f.render_widget(Paragraph::new(detail_lines).wrap(Wrap { trim: false }), detail);
}

// ─────────────────────────── overlays ───────────────────────────

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let (w, h) = (w.min(area.width), h.min(area.height));
    Rect { x: area.x + (area.width - w) / 2, y: area.y + (area.height - h) / 2, width: w, height: h }
}

fn draw_confirm(f: &mut Frame, app: &App) {
    let Some(r) = &app.confirm_restore else { return };
    let area = centered(f.area(), 60, 6);
    f.render_widget(Clear, area);
    let lines = vec![
        Line::styled(format!("Restore {}?", app.store.label(r)), bold()),
        Line::styled("Copies it into a new version and activates it. Nothing is deleted.", muted()),
        Line::from(vec![Span::styled("❯ Enter/y ", accent()), Span::raw("restore    "), Span::styled("any key ", accent()), Span::raw("cancel")]),
    ];
    f.render_widget(Paragraph::new(lines).block(Block::bordered().border_type(BorderType::Rounded).border_style(accent())), area);
}

fn draw_help(f: &mut Frame) {
    let area = centered(f.area(), 76, 22);
    f.render_widget(Clear, area);
    let h = |k: &str, d: &str| Line::from(vec![Span::styled(format!("  {k:<14}"), accent()), Span::raw(d.to_string())]);
    let lines = vec![
        h("Tab / 1-5", "Summary · DFD · Model · Chat · History"),
        h("e", "edit THREAT_MODEL.md in $EDITOR (vim) → new version on save"),
        h("v u g x", "after a change: review · keep · regenerate · discard"),
        h("Enter", "when the model is stale: refine it"),
        Line::raw(""),
        h("j/k", "Summary/DFD: select · Model: scroll · History: move"),
        h("r · d", "Model: raw markdown · diff vs previous version"),
        h("Enter · a · R", "History: open · activate · restore as new version"),
        Line::raw(""),
        h("Chat", "real model (claude CLI) with the model + repo as context"),
        h("drag files", "attach design docs (opens Chat)"),
        h("Enter / Esc", "confirm / decline a proposed change · Esc interrupts"),
        h("/regen …", "regenerate with feedback · also /refine /review /keep /discard"),
        Line::raw(""),
        Line::styled("  demo helpers: ! simulate a Map build · S toggle stale", muted()),
        Line::styled("  versions and activation are simulated in memory; the store is never written", warn()),
    ];
    f.render_widget(Paragraph::new(lines).block(Block::bordered().border_type(BorderType::Rounded).border_style(accent()).title(" keys ")), area);
}
