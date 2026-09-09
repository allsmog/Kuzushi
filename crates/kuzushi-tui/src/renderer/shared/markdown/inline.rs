use super::*;

pub(super) fn spans(nodes: &[Node<'_>], style: Style) -> Vec<Span<'static>> {
    nodes
        .iter()
        .flat_map(|node| node_spans(node, style))
        .collect()
}

fn node_spans(node: &Node<'_>, style: Style) -> Vec<Span<'static>> {
    match node {
        Node::Leaf(event) => leaf_spans(event, style),
        Node::Branch(tag, children) => branch_spans(tag, children, style),
    }
}

fn branch_spans(tag: &Tag<'_>, children: &[Node<'_>], style: Style) -> Vec<Span<'static>> {
    let mut result = spans(children, style.patch(tag_style(tag)));
    match tag {
        Tag::Link { dest_url, .. } => append_destination(&mut result, dest_url),
        Tag::Image { dest_url, .. } => {
            result.insert(0, Span::raw("Image: "));
            append_destination(&mut result, dest_url);
        }
        _ => {}
    }
    result
}

fn append_destination(spans: &mut Vec<Span<'static>>, destination: &str) {
    let label: String = spans.iter().map(|span| span.content.as_ref()).collect();
    if label != destination {
        spans.push(Span::styled(
            format!(" ({destination})"),
            modifier(Modifier::UNDERLINED),
        ));
    }
}

fn tag_style(tag: &Tag<'_>) -> Style {
    match tag {
        Tag::Strong | Tag::Heading { .. } => modifier(Modifier::BOLD),
        Tag::Emphasis => modifier(Modifier::ITALIC),
        _ => secondary_style(tag),
    }
}

fn secondary_style(tag: &Tag<'_>) -> Style {
    match tag {
        Tag::Strikethrough => modifier(Modifier::CROSSED_OUT),
        Tag::Link { .. } => modifier(Modifier::UNDERLINED),
        _ => Style::default(),
    }
}

fn leaf_spans(event: &Event<'_>, style: Style) -> Vec<Span<'static>> {
    match event {
        Event::Text(text) | Event::Html(text) | Event::InlineHtml(text) => {
            vec![Span::styled(text.to_string(), style)]
        }
        Event::Code(text) => vec![Span::styled(
            text.to_string(),
            style.add_modifier(Modifier::BOLD),
        )],
        _ => special_spans(event, style),
    }
}

fn special_spans(event: &Event<'_>, style: Style) -> Vec<Span<'static>> {
    let text = match event {
        Event::SoftBreak | Event::HardBreak => "\n".to_string(),
        Event::FootnoteReference(label) => format!("[{label}]"),
        _ => marker_text(event),
    };
    vec![Span::styled(text, style)]
}

fn marker_text(event: &Event<'_>) -> String {
    match event {
        Event::TaskListMarker(true) => "[x] ".into(),
        Event::TaskListMarker(false) => "[ ] ".into(),
        Event::Rule => "────────".into(),
        _ => String::new(),
    }
}
