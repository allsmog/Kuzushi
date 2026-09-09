use super::*;
use pulldown_cmark::CodeBlockKind;
use unicode_width::UnicodeWidthStr;

pub(super) fn render_blocks(nodes: &[Node<'_>], width: usize) -> Vec<Line<'static>> {
    let mut output = Vec::new();
    let mut pending = Vec::new();
    for node in nodes {
        if let Some(lines) = block(node, width) {
            flush_inline(&mut output, &mut pending, width);
            append_block(&mut output, lines);
        } else {
            pending.extend(inline::spans(std::slice::from_ref(node), Style::default()));
        }
    }
    flush_inline(&mut output, &mut pending, width);
    output
}

fn flush_inline(output: &mut Vec<Line<'static>>, pending: &mut Vec<Span<'static>>, width: usize) {
    if !pending.is_empty() {
        append_block(output, wrap::lines(std::mem::take(pending), width, true));
    }
}

fn append_block(output: &mut Vec<Line<'static>>, lines: Vec<Line<'static>>) {
    if !output.is_empty() {
        output.push(Line::default());
    }
    output.extend(lines);
}

fn block(node: &Node<'_>, width: usize) -> Option<Vec<Line<'static>>> {
    let Node::Branch(tag, children) = node else {
        return None;
    };
    text_block(tag, children, width).or_else(|| container_block(tag, children, width))
}

fn text_block(tag: &Tag<'_>, children: &[Node<'_>], width: usize) -> Option<Vec<Line<'static>>> {
    match tag {
        Tag::Paragraph | Tag::HtmlBlock => Some(wrap::lines(
            inline::spans(children, Style::default()),
            width,
            true,
        )),
        Tag::Heading { .. } => Some(wrap::lines(
            inline::spans(children, modifier(Modifier::BOLD | Modifier::UNDERLINED)),
            width,
            true,
        )),
        Tag::CodeBlock(kind) => Some(code_block(kind, children, width)),
        _ => None,
    }
}

fn container_block(
    tag: &Tag<'_>,
    children: &[Node<'_>],
    width: usize,
) -> Option<Vec<Line<'static>>> {
    match tag {
        Tag::List(start) => Some(list_block(*start, children, width)),
        Tag::Table(alignments) => Some(tables::render(children, alignments, width)),
        _ => quoted_block(tag, children, width),
    }
}

fn quoted_block(tag: &Tag<'_>, children: &[Node<'_>], width: usize) -> Option<Vec<Line<'static>>> {
    let prefix = match tag {
        Tag::BlockQuote(_) => "│ ".to_string(),
        Tag::FootnoteDefinition(label) => format!("[{label}] "),
        _ => return None,
    };
    Some(prefixed_block(children, &prefix, &prefix, width))
}

fn list_block(start: Option<u64>, items: &[Node<'_>], width: usize) -> Vec<Line<'static>> {
    items
        .iter()
        .enumerate()
        .flat_map(|(index, node)| {
            let prefix = start
                .map(|start| format!("{}. ", start.saturating_add(index as u64)))
                .unwrap_or_else(|| "• ".to_string());
            list_item(node, &prefix, width)
        })
        .collect()
}

fn list_item(node: &Node<'_>, prefix: &str, width: usize) -> Vec<Line<'static>> {
    let Node::Branch(_, children) = node else {
        return Vec::new();
    };
    let indent = " ".repeat(prefix.width());
    prefixed_block(children, prefix, &indent, width)
}

fn prefixed_block(
    children: &[Node<'_>],
    first: &str,
    rest: &str,
    width: usize,
) -> Vec<Line<'static>> {
    let available = width.saturating_sub(first.width());
    if available < 2 {
        let mut lines = wrap::lines(vec![Span::raw(first.to_string())], width, true);
        lines.extend(render_blocks(children, width));
        return lines;
    }
    wrap::prefixed(render_blocks(children, available), first, rest)
}

fn code_block(kind: &CodeBlockKind<'_>, children: &[Node<'_>], width: usize) -> Vec<Line<'static>> {
    let label = match kind {
        CodeBlockKind::Fenced(info) => format!(
            "Code · {}",
            info.split_whitespace().next().unwrap_or("text")
        ),
        CodeBlockKind::Indented => "Code".to_string(),
    };
    let mut output = wrap::lines(
        vec![Span::styled(label, modifier(Modifier::DIM))],
        width,
        true,
    );
    let code: String = inline::spans(children, Style::default())
        .iter()
        .map(|span| span.content.as_ref())
        .collect();
    for source_line in code.split_terminator('\n') {
        let lines = wrap::lines(
            vec![Span::raw(source_line.to_string())],
            width.saturating_sub(2).max(1),
            false,
        );
        output.extend(wrap::prefixed(lines, "│ ", "↪ "));
    }
    output
}
