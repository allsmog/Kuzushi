use super::{line_number, line_starts, rust_code_view};
use std::ops::Range;

const INVOKE_HANDLER: &str = "invoke_handler";
pub(super) const MAX_REGISTRATION_REFERENCES_PER_FILE: usize = 4_096;
const MAX_INVOKE_HANDLER_CALLS_PER_FILE: usize = 128;
const MAX_HANDLER_PATH_BYTES: usize = 1_024;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RegisteredTauriHandler {
    pub(super) path: String,
    pub(super) logical_name: String,
    pub(super) line: u32,
}

pub(super) fn registered_tauri_handlers(text: &str) -> Vec<RegisteredTauriHandler> {
    let code = rust_code_view(text);
    let line_starts = line_starts(&code);
    let mut handlers = Vec::new();
    let argument_spans = invoke_handler_argument_spans(&code);
    if argument_spans.len() > MAX_INVOKE_HANDLER_CALLS_PER_FILE {
        return Vec::new();
    }
    for arguments in argument_spans {
        let Some(body) = direct_generate_handler_body(&code, arguments) else {
            continue;
        };
        handlers.extend(handler_entries(&code, body, &line_starts));
        if handlers.len() > MAX_REGISTRATION_REFERENCES_PER_FILE {
            return Vec::new();
        }
    }
    handlers
}

fn invoke_handler_argument_spans(code: &str) -> Vec<Range<usize>> {
    code.match_indices(INVOKE_HANDLER)
        .filter(|(offset, _)| token_is_bounded(code, *offset, INVOKE_HANDLER.len()))
        .filter(|(offset, _)| preceded_by_method_dot(code, *offset))
        .filter_map(|(offset, _)| invocation_arguments(code, offset + INVOKE_HANDLER.len()))
        .take(MAX_INVOKE_HANDLER_CALLS_PER_FILE + 1)
        .collect()
}

fn preceded_by_method_dot(code: &str, offset: usize) -> bool {
    code.get(..offset)
        .and_then(|prefix| prefix.chars().rev().find(|character| !character.is_whitespace()))
        == Some('.')
}

fn invocation_arguments(code: &str, after_name: usize) -> Option<Range<usize>> {
    let open = skip_whitespace(code, after_name, code.len());
    (code.as_bytes().get(open) == Some(&b'('))
        .then(|| balanced_contents(code, open, b'(', b')'))?
}

fn direct_generate_handler_body(code: &str, arguments: Range<usize>) -> Option<Range<usize>> {
    let arguments = trim_trailing_comma(code, trim_span(code, arguments));
    let mut cursor = arguments.start;
    consume_syntax(code, &mut cursor, arguments.end, "tauri")?;
    consume_syntax(code, &mut cursor, arguments.end, "::")?;
    consume_syntax(code, &mut cursor, arguments.end, "generate_handler")?;
    consume_syntax(code, &mut cursor, arguments.end, "!")?;
    cursor = skip_whitespace(code, cursor, arguments.end);
    let body = balanced_contents(code, cursor, b'[', b']')?;
    let end = skip_whitespace(code, body.end + 1, arguments.end);
    (end == arguments.end).then_some(body)
}

fn consume_syntax(code: &str, cursor: &mut usize, end: usize, syntax: &str) -> Option<()> {
    *cursor = skip_whitespace(code, *cursor, end);
    let suffix = code.get(*cursor..end)?;
    suffix.starts_with(syntax).then_some(())?;
    *cursor += syntax.len();
    Some(())
}

fn balanced_contents(code: &str, open: usize, left: u8, right: u8) -> Option<Range<usize>> {
    (code.as_bytes().get(open) == Some(&left)).then_some(())?;
    let mut depth = 0usize;
    for (relative, byte) in code.as_bytes().get(open..)?.iter().enumerate() {
        depth += usize::from(*byte == left);
        depth = depth.checked_sub(usize::from(*byte == right))?;
        if depth == 0 {
            return Some(open + 1..open + relative);
        }
    }
    None
}

fn handler_entries(
    code: &str,
    body: Range<usize>,
    line_starts: &[usize],
) -> Vec<RegisteredTauriHandler> {
    code[body.clone()]
        .split(',')
        .scan(body.start, |offset, entry| {
            let start = *offset;
            *offset += entry.len() + 1;
            Some((start, entry))
        })
        .filter_map(|(offset, entry)| registered_handler(entry, offset, line_starts))
        .take(MAX_REGISTRATION_REFERENCES_PER_FILE + 1)
        .collect()
}

fn registered_handler(
    entry: &str,
    offset: usize,
    line_starts: &[usize],
) -> Option<RegisteredTauriHandler> {
    let leading = entry.len() - entry.trim_start().len();
    let path = compact_handler_path(entry)?;
    let logical_name = path.rsplit("::").next()?.to_string();
    Some(RegisteredTauriHandler {
        path,
        logical_name,
        line: line_number(line_starts, offset + leading),
    })
}

fn compact_handler_path(entry: &str) -> Option<String> {
    (entry.len() <= MAX_HANDLER_PATH_BYTES).then_some(())?;
    let path = entry
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let segments = path.split("::").collect::<Vec<_>>();
    (!segments.is_empty() && segments.iter().all(|segment| valid_identifier(segment)))
        .then_some(path)
}

fn valid_identifier(segment: &str) -> bool {
    let identifier = segment.strip_prefix("r#").unwrap_or(segment);
    let mut characters = identifier.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

fn trim_span(code: &str, span: Range<usize>) -> Range<usize> {
    let text = &code[span.clone()];
    let leading = text.len() - text.trim_start().len();
    let trailing = text.len() - text.trim_end().len();
    span.start + leading..span.end - trailing
}

fn trim_trailing_comma(code: &str, span: Range<usize>) -> Range<usize> {
    if code.as_bytes().get(span.end.saturating_sub(1)) != Some(&b',') {
        return span;
    }
    trim_span(code, span.start..span.end - 1)
}

fn skip_whitespace(code: &str, mut cursor: usize, end: usize) -> usize {
    while cursor < end && code.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

fn token_is_bounded(code: &str, offset: usize, length: usize) -> bool {
    !code[..offset]
        .chars()
        .next_back()
        .is_some_and(identifier_character)
        && !code[offset + length..]
            .chars()
            .next()
            .is_some_and(identifier_character)
}

fn identifier_character(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}
