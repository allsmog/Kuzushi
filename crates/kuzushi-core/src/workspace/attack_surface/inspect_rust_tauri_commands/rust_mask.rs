#[derive(Clone, Copy)]
enum RustMaskState {
    Code,
    LineComment,
    BlockComment(usize),
    String { escaped: bool },
    RawString { hashes: usize },
}

/// Preserve Rust code and line breaks while masking strings, comments, and
/// character literals. The parser can then inspect byte-identical offsets
/// without promoting source embedded in docs or fixtures.
pub(super) fn rust_code_view(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut masked = bytes.to_vec();
    let mut state = RustMaskState::Code;
    let mut index = 0;
    while index < bytes.len() {
        let (next, next_state) = mask_next_token(bytes, &mut masked, index, state);
        index = next;
        state = next_state;
    }
    String::from_utf8(masked).expect("masking preserves UTF-8 byte structure")
}

fn mask_next_token(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
    state: RustMaskState,
) -> (usize, RustMaskState) {
    match state {
        RustMaskState::Code => mask_code_token(bytes, masked, index),
        RustMaskState::LineComment => mask_line_comment(bytes, masked, index),
        RustMaskState::BlockComment(depth) => mask_block_comment(bytes, masked, index, depth),
        RustMaskState::String { escaped } => mask_string(bytes, masked, index, escaped),
        RustMaskState::RawString { hashes } => mask_raw_string(bytes, masked, index, hashes),
    }
}

fn mask_code_token(bytes: &[u8], masked: &mut [u8], index: usize) -> (usize, RustMaskState) {
    if let Some(comment) = mask_comment_start(bytes, masked, index) {
        return comment;
    }
    if let Some(literal) = mask_literal_start(bytes, masked, index) {
        return literal;
    }
    (index + 1, RustMaskState::Code)
}

fn mask_comment_start(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
) -> Option<(usize, RustMaskState)> {
    let state = if starts_with(bytes, index, b"//") {
        RustMaskState::LineComment
    } else if starts_with(bytes, index, b"/*") {
        RustMaskState::BlockComment(1)
    } else {
        return None;
    };
    mask_range(masked, index, 2);
    Some((index + 2, state))
}

fn mask_literal_start(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
) -> Option<(usize, RustMaskState)> {
    if let Some((length, hashes)) = raw_string_start(bytes, index) {
        mask_range(masked, index, length);
        return Some((index + length, RustMaskState::RawString { hashes }));
    }
    if bytes[index] == b'"' {
        masked[index] = b' ';
        return Some((index + 1, RustMaskState::String { escaped: false }));
    }
    let length = char_literal_length(bytes, index)?;
    mask_range(masked, index, length);
    Some((index + length, RustMaskState::Code))
}

fn mask_line_comment(bytes: &[u8], masked: &mut [u8], index: usize) -> (usize, RustMaskState) {
    if bytes[index] == b'\n' {
        return (index + 1, RustMaskState::Code);
    }
    masked[index] = b' ';
    (index + 1, RustMaskState::LineComment)
}

fn mask_block_comment(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
    depth: usize,
) -> (usize, RustMaskState) {
    if starts_with(bytes, index, b"/*") {
        mask_range(masked, index, 2);
        return (index + 2, RustMaskState::BlockComment(depth + 1));
    }
    if starts_with(bytes, index, b"*/") {
        mask_range(masked, index, 2);
        let next = depth.saturating_sub(1);
        return (index + 2, block_comment_state(next));
    }
    mask_byte(masked, index);
    (index + 1, RustMaskState::BlockComment(depth))
}

fn block_comment_state(depth: usize) -> RustMaskState {
    if depth == 0 {
        RustMaskState::Code
    } else {
        RustMaskState::BlockComment(depth)
    }
}

fn mask_string(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
    escaped: bool,
) -> (usize, RustMaskState) {
    let byte = bytes[index];
    mask_byte(masked, index);
    if escaped {
        return (index + 1, RustMaskState::String { escaped: false });
    }
    match byte {
        b'\\' => (index + 1, RustMaskState::String { escaped: true }),
        b'"' => (index + 1, RustMaskState::Code),
        _ => (index + 1, RustMaskState::String { escaped: false }),
    }
}

fn mask_raw_string(
    bytes: &[u8],
    masked: &mut [u8],
    index: usize,
    hashes: usize,
) -> (usize, RustMaskState) {
    if raw_string_end(bytes, index, hashes) {
        let length = hashes + 1;
        mask_range(masked, index, length);
        return (index + length, RustMaskState::Code);
    }
    mask_byte(masked, index);
    (index + 1, RustMaskState::RawString { hashes })
}

fn raw_string_start(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let raw_index = match bytes.get(index) {
        Some(b'r') => index,
        Some(b'b' | b'c') if bytes.get(index + 1) == Some(&b'r') => index + 1,
        _ => return None,
    };
    let hashes = bytes[raw_index + 1..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    let quote = raw_index + hashes + 1;
    (bytes.get(quote) == Some(&b'"')).then_some((quote - index + 1, hashes))
}

fn raw_string_end(bytes: &[u8], index: usize, hashes: usize) -> bool {
    bytes.get(index) == Some(&b'"')
        && bytes
            .get(index + 1..index + hashes + 1)
            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
}

fn char_literal_length(bytes: &[u8], index: usize) -> Option<usize> {
    (bytes.get(index) == Some(&b'\''))
        .then_some(())
        .and_then(|_| char_literal_content_length(bytes.get(index + 1..)?))
        .filter(|length| bytes.get(index + length + 1) == Some(&b'\''))
        .map(|length| length + 2)
}

fn char_literal_content_length(content: &[u8]) -> Option<usize> {
    match content.first()? {
        b'\\' => escaped_char_length(content),
        byte => utf8_scalar_width(*byte),
    }
}

fn escaped_char_length(content: &[u8]) -> Option<usize> {
    match content.get(1)? {
        b'x' => (content.len() >= 4).then_some(4),
        b'u' if content.get(2) == Some(&b'{') => content
            .iter()
            .skip(3)
            .position(|byte| *byte == b'}')
            .map(|offset| offset + 4),
        _ => Some(2),
    }
}

fn utf8_scalar_width(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc0..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf7 => Some(4),
        _ => None,
    }
}

fn starts_with(bytes: &[u8], index: usize, token: &[u8]) -> bool {
    bytes.get(index..index + token.len()) == Some(token)
}

fn mask_range(masked: &mut [u8], index: usize, length: usize) {
    for offset in 0..length {
        mask_byte(masked, index + offset);
    }
}

fn mask_byte(masked: &mut [u8], index: usize) {
    if masked[index] != b'\n' {
        masked[index] = b' ';
    }
}
