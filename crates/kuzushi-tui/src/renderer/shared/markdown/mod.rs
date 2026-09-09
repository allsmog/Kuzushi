use pulldown_cmark::{Event, Options, Parser, Tag};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

mod blocks;
mod inline;
mod tables;
use super::text::styled_wrap as wrap;

enum Node<'a> {
    Branch(Tag<'a>, Vec<Node<'a>>),
    Leaf(Event<'a>),
}

/// A width-bound presentation of the answer. Raw conversation text is retained
/// by the chat state; both plain and terminal output consume this projection.
pub(crate) fn answer_markdown(text: &str, width: usize) -> Vec<Line<'static>> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_FOOTNOTES;
    let mut events = Parser::new_ext(text, options);
    let Some(nodes) = read_nodes(&mut events, 0) else {
        return wrap::lines(vec![Span::raw(text.to_string())], width.max(1), true);
    };
    blocks::render_blocks(&nodes, width.max(1))
}

fn read_nodes<'a>(
    events: &mut impl Iterator<Item = Event<'a>>,
    depth: usize,
) -> Option<Vec<Node<'a>>> {
    if depth > 64 {
        return None;
    }
    let mut nodes = Vec::new();
    while let Some(event) = events.next() {
        match event {
            Event::Start(tag) => nodes.push(Node::Branch(tag, read_nodes(events, depth + 1)?)),
            Event::End(_) => break,
            event => nodes.push(Node::Leaf(event)),
        }
    }
    Some(nodes)
}

fn modifier(value: Modifier) -> Style {
    Style::default().add_modifier(value)
}

#[cfg(test)]
mod tests;
