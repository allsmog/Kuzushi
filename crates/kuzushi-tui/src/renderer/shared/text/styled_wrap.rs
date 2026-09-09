use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Clone)]
struct Glyph {
    text: String,
    style: Style,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BreakMode {
    Characters,
    Words,
    PreserveWords,
}

pub(in crate::renderer::shared) fn lines(
    spans: Vec<Span<'static>>,
    width: usize,
    words: bool,
) -> Vec<Line<'static>> {
    let mode = if words {
        BreakMode::Words
    } else {
        BreakMode::Characters
    };
    wrapped_lines(spans, width, mode)
}

pub(super) fn document_line(line: Line<'static>, width: usize) -> Vec<Line<'static>> {
    let spans = line
        .spans
        .into_iter()
        .map(|mut span| {
            span.style = line.style.patch(span.style);
            span
        })
        .collect();
    let mut lines = wrapped_lines(spans, width, BreakMode::PreserveWords);
    for row in &mut lines {
        row.alignment = line.alignment;
    }
    lines
}

fn wrapped_lines(spans: Vec<Span<'static>>, width: usize, mode: BreakMode) -> Vec<Line<'static>> {
    let mut result = Vec::new();
    let glyphs = glyphs(spans);
    for paragraph in glyphs.split(|glyph| glyph.text == "\n") {
        result.extend(wrap_line(paragraph, width.max(1), mode));
    }
    result
}

fn glyphs(spans: Vec<Span<'static>>) -> Vec<Glyph> {
    spans
        .into_iter()
        .flat_map(|span| {
            safe_text(&span.content)
                .graphemes(true)
                .map(|text| Glyph {
                    text: text.into(),
                    style: span.style,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn safe_text(text: &str) -> String {
    text.chars().map(safe_character).collect()
}

fn safe_character(ch: char) -> String {
    match ch {
        '\n' => "\n".into(),
        '\t' => "    ".into(),
        ch if ch.is_control() => ch.escape_default().to_string(),
        ch => ch.to_string(),
    }
}

fn wrap_line(glyphs: &[Glyph], width: usize, mode: BreakMode) -> Vec<Line<'static>> {
    let mut result = Vec::new();
    let mut remaining = glyphs;
    while !remaining.is_empty() {
        let end = fitting_end(remaining, width);
        let (draw, next) = word_boundary(remaining, end, mode);
        result.push(glyph_line(&remaining[..draw]));
        remaining = &remaining[next..];
    }
    if result.is_empty() {
        result.push(Line::default());
    }
    result
}

fn fitting_end(glyphs: &[Glyph], width: usize) -> usize {
    let mut used = 0;
    glyphs
        .iter()
        .take_while(|glyph| {
            used += glyph.text.width();
            used <= width
        })
        .count()
        .max(1)
}

fn word_boundary(glyphs: &[Glyph], end: usize, mode: BreakMode) -> (usize, usize) {
    if mode == BreakMode::Characters || end == glyphs.len() {
        return (end, end);
    }
    let boundary = glyphs[..end].iter().rposition(|glyph| glyph.text == " ");
    match boundary {
        Some(index) if index > 0 => (
            index + usize::from(mode == BreakMode::PreserveWords),
            index + 1,
        ),
        _ => (end, end),
    }
}

fn glyph_line(glyphs: &[Glyph]) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    for glyph in glyphs {
        append_glyph(&mut spans, glyph);
    }
    Line::from(spans)
}

fn append_glyph(spans: &mut Vec<Span<'static>>, glyph: &Glyph) {
    if let Some(last) = spans.last_mut().filter(|span| span.style == glyph.style) {
        last.content.to_mut().push_str(&glyph.text);
    } else {
        spans.push(Span::styled(glyph.text.clone(), glyph.style));
    }
}

pub(in crate::renderer::shared) fn prefixed(
    lines: Vec<Line<'static>>,
    first: &str,
    rest: &str,
) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .enumerate()
        .map(|(index, mut line)| {
            let prefix = if index == 0 { first } else { rest };
            line.spans.insert(0, Span::raw(prefix.to_string()));
            line
        })
        .collect()
}
