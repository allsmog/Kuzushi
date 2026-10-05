use super::{char_index_to_byte, is_word_char};
use unicode_segmentation::UnicodeSegmentation;

// Public editor offsets remain scalar indices for existing view models. Only
// extended-grapheme boundaries are valid cursor positions within that space.
fn boundaries(text: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(text.graphemes(true).scan(0, |offset, grapheme| {
        *offset += grapheme.chars().count();
        Some(*offset)
    }))
}

pub(super) fn floor(text: &str, cursor: usize) -> usize {
    boundaries(text)
        .take_while(|at| *at <= cursor)
        .last()
        .unwrap_or(0)
}

pub(super) fn ceil(text: &str, cursor: usize) -> usize {
    boundaries(text)
        .find(|at| *at >= cursor)
        .unwrap_or_else(|| text.chars().count())
}

pub(super) fn previous(text: &str, cursor: usize) -> usize {
    boundaries(text)
        .take_while(|at| *at < cursor)
        .last()
        .unwrap_or(0)
}

pub(super) fn next(text: &str, cursor: usize) -> usize {
    boundaries(text)
        .find(|at| *at > cursor)
        .unwrap_or_else(|| text.chars().count())
}

fn word(grapheme: &str) -> bool {
    grapheme.chars().any(is_word_char)
}

pub(super) fn word_left(text: &str, cursor: usize) -> usize {
    let prefix = &text[..char_index_to_byte(text, cursor)];
    let byte = prefix
        .grapheme_indices(true)
        .rev()
        .skip_while(|(_, grapheme)| !word(grapheme))
        .take_while(|(_, grapheme)| word(grapheme))
        .last()
        .map_or(0, |(offset, _)| offset);
    prefix[..byte].chars().count()
}

pub(super) fn word_right(text: &str, cursor: usize) -> usize {
    let suffix = &text[char_index_to_byte(text, cursor)..];
    let byte = suffix
        .grapheme_indices(true)
        .skip_while(|(_, grapheme)| word(grapheme))
        .find(|(_, grapheme)| word(grapheme))
        .map_or(suffix.len(), |(offset, _)| offset);
    cursor + suffix[..byte].chars().count()
}
