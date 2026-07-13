use super::KwpError;
use std::io::Read;
use std::thread::{self, JoinHandle};

const STDERR_READ_BUFFER_BYTES: usize = 8 * 1024;
const STDERR_LINE_PREVIEW_BYTES: usize = 8 * 1024;
const STDERR_TOTAL_PREVIEW_BYTES: usize = 64 * 1024;

pub(super) struct SupervisedStderr {
    label: String,
    drain: JoinHandle<std::io::Result<DrainSummary>>,
}

impl SupervisedStderr {
    pub(super) fn spawn(reader: impl Read + Send + 'static, label: String) -> Self {
        let thread_label = label.clone();
        let drain = thread::spawn(move || {
            drain_stderr(reader, |line, truncated| {
                if truncated {
                    eprintln!("{thread_label} {line}… [line truncated]");
                } else {
                    eprintln!("{thread_label} {line}");
                }
            })
        });
        Self { label, drain }
    }

    pub(super) fn join(self) -> Result<(), KwpError> {
        let summary = self
            .drain
            .join()
            .map_err(|_| KwpError::Internal(format!("{} drain thread panicked", self.label)))?
            .map_err(|error| KwpError::Internal(format!("{} drain failed: {error}", self.label)))?;
        if summary.total_truncated {
            eprintln!(
                "{} preview truncated after {} bytes; drained {} bytes total",
                self.label, STDERR_TOTAL_PREVIEW_BYTES, summary.drained_bytes
            );
        }
        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DrainSummary {
    drained_bytes: u64,
    total_truncated: bool,
}

#[derive(Default)]
struct PreviewState {
    line: Vec<u8>,
    line_bytes: usize,
    preview_bytes: usize,
    line_truncated: bool,
    total_truncated: bool,
}

fn drain_stderr(
    mut reader: impl Read,
    mut emit: impl FnMut(&str, bool),
) -> std::io::Result<DrainSummary> {
    let mut buffer = [0_u8; STDERR_READ_BUFFER_BYTES];
    let mut state = PreviewState::default();
    let mut drained_bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        drained_bytes = drained_bytes.saturating_add(read as u64);
        for byte in &buffer[..read] {
            consume_stderr_byte(*byte, &mut state, &mut emit);
        }
    }
    emit_final_line(&mut state, &mut emit);
    Ok(DrainSummary {
        drained_bytes,
        total_truncated: state.total_truncated,
    })
}

fn consume_stderr_byte(byte: u8, state: &mut PreviewState, emit: &mut impl FnMut(&str, bool)) {
    if state.preview_bytes >= STDERR_TOTAL_PREVIEW_BYTES {
        state.total_truncated = true;
        return;
    }
    state.preview_bytes += 1;
    if byte == b'\n' {
        emit_current_line(state, emit);
        return;
    }
    state.line_bytes += 1;
    if state.line.len() < STDERR_LINE_PREVIEW_BYTES {
        state.line.push(byte);
    } else {
        state.line_truncated = true;
    }
}

fn emit_current_line(state: &mut PreviewState, emit: &mut impl FnMut(&str, bool)) {
    let line = escape_child_diagnostic(&state.line);
    emit(&line, state.line_truncated);
    state.line.clear();
    state.line_bytes = 0;
    state.line_truncated = false;
}

pub(super) fn escape_child_diagnostic(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len());
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                push_safe_text(&mut escaped, text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                push_safe_text(&mut escaped, valid_utf8_prefix(remaining, valid));
                let invalid = error.error_len().unwrap_or(remaining.len() - valid);
                push_escaped_bytes(&mut escaped, &remaining[valid..valid + invalid]);
                remaining = &remaining[valid + invalid..];
            }
        }
    }
    escaped
}

fn valid_utf8_prefix(bytes: &[u8], length: usize) -> &str {
    std::str::from_utf8(&bytes[..length]).expect("UTF-8 error valid prefix must be valid")
}

fn push_safe_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\t' => output.push('\t'),
            '\r' => output.push_str("\\r"),
            '\u{1b}' => output.push_str("\\x1b"),
            control if control.is_control() => push_escaped_control(output, control),
            printable => output.push(printable),
        }
    }
}

fn push_escaped_control(output: &mut String, control: char) {
    use std::fmt::Write as _;
    let _ = write!(output, "\\u{{{:04x}}}", control as u32);
}

fn push_escaped_bytes(output: &mut String, bytes: &[u8]) {
    use std::fmt::Write as _;
    for byte in bytes {
        let _ = write!(output, "\\x{byte:02x}");
    }
}

fn emit_final_line(state: &mut PreviewState, emit: &mut impl FnMut(&str, bool)) {
    if !state.line.is_empty() || state.line_bytes > 0 {
        emit_current_line(state, emit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Error};

    #[test]
    fn newline_free_stderr_has_a_bounded_preview_and_is_fully_drained() {
        let input = vec![b'x'; STDERR_TOTAL_PREVIEW_BYTES * 3];
        let mut previews = Vec::new();

        let summary = drain_stderr(Cursor::new(&input), |line, truncated| {
            previews.push((line.len(), truncated));
        })
        .unwrap();

        assert_eq!(summary.drained_bytes, input.len() as u64);
        assert!(summary.total_truncated);
        assert_eq!(previews, vec![(STDERR_LINE_PREVIEW_BYTES, true)]);
    }

    #[test]
    fn drain_continues_after_total_preview_truncation() {
        let input = vec![b'a'; STDERR_TOTAL_PREVIEW_BYTES + STDERR_READ_BUFFER_BYTES];
        let summary = drain_stderr(Cursor::new(&input), |_, _| {}).unwrap();

        assert_eq!(summary.drained_bytes, input.len() as u64);
        assert!(summary.total_truncated);
    }

    #[test]
    fn join_surfaces_reader_and_thread_failures() {
        let reader = SupervisedStderr::spawn(FailingReader, "test stderr".to_string());
        assert!(reader
            .join()
            .unwrap_err()
            .to_string()
            .contains("drain failed"));

        let panicked = SupervisedStderr {
            label: "test stderr".to_string(),
            drain: thread::spawn(|| panic!("boom")),
        };
        assert!(panicked
            .join()
            .unwrap_err()
            .to_string()
            .contains("drain thread panicked"));
    }

    #[test]
    fn terminal_controls_are_visible_text_and_unicode_is_preserved() {
        let input = concat!(
            "unicode: 雪\t",
            "\u{1b}[31mred\u{1b}[0m",
            "\u{1b}]52;c;secret\u{7}",
            "\r\u{0}\u{85}\u{9b}"
        );

        let escaped = escape_child_diagnostic(input.as_bytes());

        assert_eq!(
            escaped,
            "unicode: 雪\t\\x1b[31mred\\x1b[0m\\x1b]52;c;secret\\u{0007}\\r\\u{0000}\\u{0085}\\u{009b}"
        );
        assert!(!escaped.contains('\u{1b}'));
        assert!(!escaped.contains('\r'));
    }

    #[test]
    fn invalid_utf8_is_escaped_byte_for_byte() {
        assert_eq!(
            escape_child_diagnostic(&[b'o', b'k', b' ', 0xff, 0xc3, b'(']),
            "ok \\xff\\xc3("
        );
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(Error::other("synthetic read failure"))
        }
    }
}
