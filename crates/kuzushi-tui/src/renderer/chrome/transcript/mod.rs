pub(in crate::renderer) use super::*;

pub(crate) fn render_transcript(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.height == 0 {
        return;
    }
    render_lines(frame, area, transcript_lines(app, area.height as usize));
}

pub(crate) fn transcript_lines(app: &ShellApp, visible: usize) -> Vec<Line<'static>> {
    if visible == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in &app.log {
        let body_lines = if line.body.is_empty() {
            vec![""]
        } else {
            line.body.lines().collect::<Vec<_>>()
        };
        for (index, body) in body_lines.into_iter().enumerate() {
            rows.push(transcript_line_dated(
                &line.prefix,
                body,
                index > 0,
                line.time_secs,
            ));
        }
    }
    let start = rows.len().saturating_sub(visible);
    rows.into_iter().skip(start).collect()
}

pub(crate) fn transcript_line(prefix: &str, body: &str, continuation: bool) -> Line<'static> {
    transcript_line_dated(prefix, body, continuation, 0)
}

/// `transcript_line` with an optional wall-clock timestamp prefix, matching
/// `design/mockups/_shared.jsx::logLine`:
///
///   ` 14:32:14  ⏵ run  body…`
///     subtle     glyph subtle  body
///
/// `time_secs == 0` skips the timestamp so synthetic lines (built inside
/// the renderer for context-free hints) stay terse.
pub(crate) fn transcript_line_dated(
    prefix: &str,
    body: &str,
    continuation: bool,
    time_secs: u64,
) -> Line<'static> {
    let (glyph, style, show_label) = transcript_glyph(prefix, continuation);
    let mut spans: Vec<Span<'static>> = Vec::new();
    if time_secs != 0 {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(wall_hms(time_secs), theme::subtle()));
    }
    spans.push(Span::styled(format!(" {glyph} "), style));
    if show_label {
        spans.push(Span::styled(prefix.to_string(), theme::subtle()));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        body.to_string(),
        transcript_body_style(prefix),
    ));
    Line::from(spans)
}

/// Format wall-clock seconds-since-epoch as `HH:MM:SS` (UTC).  Used by
/// transcript timestamps; keeping it UTC keeps log-comparison across
/// machines deterministic without a timezone database.
pub(crate) fn wall_hms(time_secs: u64) -> String {
    let day_secs = time_secs % 86_400;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

pub(crate) fn transcript_glyph(prefix: &str, continuation: bool) -> (&'static str, Style, bool) {
    // Glyph + color mapping mirrors `design/mockups/_shared.jsx::logLine`:
    //   in:    ●  c-accent     (operator input echo)
    //   run:   ⏵  c-primary    (tool/module dispatch)
    //   ok:    ✓  c-success    (success)
    //   err:   ✗  c-danger     (failure)
    //   agent: ◆  c-accent     (LLM message)
    //   flow:  …  c-muted      (streaming/in-flight)
    //   find:  ▸  c-warn       (finding)
    //   log:   ·  c-subtle     (ambient/log)
    if continuation {
        return ("…", theme::muted(), false);
    }
    match prefix {
        ">" => ("●", theme::accent(), false),
        "tool" | "scan" | "run" | "resume" | "pause" => ("⏵", theme::primary(), true),
        "ok" | "success" | "done" => ("✓", theme::success(), true),
        "result" | "answer" | "agent" | "plan" | "threats" | "activity" => {
            ("◆", theme::accent(), true)
        }
        "finding" | "open" | "title" | "triage" | "aliases" => ("▸", theme::warn(), true),
        "error" => ("✗", theme::danger(), true),
        "system" | "startup" | "first-run" | "help" | "view" | "module" | "prompt" | "tune"
        | "target" | "workspace" | "context" | "history" | "quickstart" | "auth" | "model"
        | "provider" | "backend" | "cost" | "load" | "runs" | "replay" | "trace" => {
            ("·", theme::muted(), true)
        }
        _ => ("·", theme::subtle(), true),
    }
}

pub(crate) fn transcript_body_style(prefix: &str) -> Style {
    match prefix {
        "error" => theme::danger(),
        "finding" | "open" => theme::warn(),
        "result" | "answer" | "agent" | "activity" => theme::primary(),
        _ => Style::default(),
    }
}
