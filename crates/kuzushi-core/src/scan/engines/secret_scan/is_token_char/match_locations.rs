pub(in crate::scan::engines::secret_scan) fn locate_match(
    text: &str,
    index: usize,
) -> MatchLocation {
    let mut line = 1u32;
    let mut line_start = 0usize;
    for (cursor, byte) in text.as_bytes().iter().copied().enumerate().take(index) {
        if byte == b'\n' {
            line += 1;
            line_start = cursor + 1;
        }
    }
    let line_end = text[line_start..]
        .find('\n')
        .map(|offset| line_start + offset)
        .unwrap_or(text.len());
    MatchLocation {
        line,
        line_text: text[line_start..line_end].to_string(),
    }
}

#[derive(Debug, Clone)]
pub(in crate::scan::engines::secret_scan) struct MatchLocation {
    pub(in crate::scan::engines::secret_scan) line: u32,
    pub(in crate::scan::engines::secret_scan) line_text: String,
}
