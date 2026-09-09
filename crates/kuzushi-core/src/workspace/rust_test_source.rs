//! A conservative source projection for production surface discovery.
//!
//! Only direct built-in test attributes establish exclusion. Unknown macros,
//! compound cfg expressions, cross-file module ownership and malformed scopes
//! remain visible; this is not a proof that retained code is reachable.

use std::borrow::Cow;
use std::ops::Range;
use tree_sitter::{Node, Parser, Tree};

pub(crate) fn surface_source<'a>(language: &str, text: &'a str) -> Cow<'a, str> {
    if language != "Rust" {
        return Cow::Borrowed(text);
    }
    let Some(tree) = parse(text) else {
        return Cow::Borrowed(text);
    };
    let ranges = test_ranges(tree.root_node(), text);
    if ranges.is_empty() {
        return Cow::Borrowed(text);
    }
    Cow::Owned(blank_ranges(text, ranges))
}

fn parse(text: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(text, None)
}

fn test_ranges(root: Node<'_>, text: &str) -> Vec<Range<usize>> {
    let mut pending = vec![root];
    let mut ranges = Vec::new();
    while let Some(node) = pending.pop() {
        if let Some(range) = test_scope_range(node, text) {
            ranges.push(range);
        } else {
            pending.extend(node.named_children(&mut node.walk()));
        }
    }
    ranges
}

fn test_scope_range(node: Node<'_>, text: &str) -> Option<Range<usize>> {
    if node.has_error() {
        return None;
    }
    if has_inner_test_cfg(node, text) {
        return Some(node.byte_range());
    }
    outer_test_scope_range(node, text)
}

fn has_inner_test_cfg(node: Node<'_>, text: &str) -> bool {
    let node = node.child_by_field_name("body").unwrap_or(node);
    node.named_children(&mut node.walk())
        .any(|child| child.kind() == "inner_attribute_item" && test_attribute(child, text, false))
}

fn outer_test_scope_range(node: Node<'_>, text: &str) -> Option<Range<usize>> {
    if !node.kind().ends_with("_item") {
        return None;
    }
    let attributes = preceding_attributes(node);
    let is_function = node.kind() == "function_item";
    attributes
        .iter()
        .any(|attr| test_attribute(*attr, text, is_function))
        .then(|| {
            attributes
                .last()
                .map_or(node.start_byte(), Node::start_byte)..node.end_byte()
        })
}

fn preceding_attributes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut attributes = Vec::new();
    let mut previous = node.prev_named_sibling();
    while let Some(sibling) = previous {
        match sibling.kind() {
            "attribute_item" => attributes.push(sibling),
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        previous = sibling.prev_named_sibling();
    }
    attributes
}

fn test_attribute(item: Node<'_>, text: &str, is_function: bool) -> bool {
    let Some(attribute) = item.named_child(0) else {
        return false;
    };
    match attribute_name(attribute, text) {
        Some("cfg") => direct_test_cfg(attribute, text),
        Some("test") => is_function && attribute.named_child_count() == 1,
        _ => false,
    }
}

fn attribute_name<'a>(attribute: Node<'_>, text: &'a str) -> Option<&'a str> {
    let name = attribute.named_child(0)?;
    text.get(name.byte_range())
}

fn direct_test_cfg(attribute: Node<'_>, text: &str) -> bool {
    let Some(arguments) = attribute.child_by_field_name("arguments") else {
        return false;
    };
    text[arguments.byte_range()]
        .split_whitespace()
        .collect::<String>()
        == "(test)"
}

fn blank_ranges(text: &str, ranges: Vec<Range<usize>>) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for range in ranges {
        bytes[range].iter_mut().for_each(blank_byte);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn blank_byte(byte: &mut u8) {
    if !matches!(*byte, b'\n' | b'\r') {
        *byte = b' ';
    }
}

#[cfg(test)]
mod tests;
