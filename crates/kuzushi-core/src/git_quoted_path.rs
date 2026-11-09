//! Decoding of git's C-style quoted path names.
//!
//! Git wraps a path name in double quotes with C escapes whenever the name
//! holds a byte it must not emit literally — a double quote, a backslash, a
//! control character, or (with the default `core.quotePath`) any byte above
//! ASCII. So `src/café.rs` reaches a reader as `"src/caf\303\251.rs"`, and a
//! reader that keeps the raw text is holding the name of a file that does not
//! exist.
//!
//! A consumer that can ask git for NUL-separated output (`-z`) gets the raw
//! bytes and needs none of this. This is for the names that only exist inside
//! diff text, where the quoting is part of the format: the `diff --git`,
//! `---`/`+++`, and `rename`/`copy` headers.

use anyhow::{bail, Result};

/// The quoted name `raw` begins with, plus the text after its closing quote.
///
/// `Ok(None)` when `raw` does not start with a quote, so the caller can read
/// the unquoted name itself. Malformed quoting is an error rather than a
/// half-decoded name, because a half-decoded name names a different file than
/// the diff does.
pub(crate) fn take_quoted_path(raw: &str) -> Result<Option<(String, &str)>> {
    let Some(body) = raw.strip_prefix('"') else {
        return Ok(None);
    };
    let Some(end) = closing_quote(body) else {
        bail!("git quoted path is missing its closing quote: {raw:?}");
    };
    Ok(Some((decode_escapes(&body[..end])?, &body[end + 1..])))
}

/// Byte offset of the quote that closes the name, skipping an escaped one.
fn closing_quote(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some(index),
            b'\\' => index += 2,
            _ => index += 1,
        }
    }
    None
}

/// Git's `quote_c_style` escapes, read back. An octal escape carries one raw
/// byte of the name, so the body is decoded as bytes and then required to be
/// UTF-8: a name this process cannot even spell is an error, not a guess.
fn decode_escapes(body: &str) -> Result<String> {
    let mut decoded = Vec::with_capacity(body.len());
    let mut rest = body.as_bytes();
    while let Some((&head, tail)) = rest.split_first() {
        rest = match head {
            b'\\' => take_escape(&mut decoded, tail)?,
            literal => take_literal(&mut decoded, literal, tail),
        };
    }
    String::from_utf8(decoded)
        .map_err(|_| anyhow::anyhow!("git quoted path is not valid UTF-8: {body:?}"))
}

fn take_literal<'a>(decoded: &mut Vec<u8>, literal: u8, tail: &'a [u8]) -> &'a [u8] {
    decoded.push(literal);
    tail
}

/// One escape, read from just after its backslash: an octal byte, or one of
/// the single-letter escapes git emits.
fn take_escape<'a>(decoded: &mut Vec<u8>, tail: &'a [u8]) -> Result<&'a [u8]> {
    if let Some((byte, rest)) = octal_escape(tail) {
        decoded.push(byte);
        return Ok(rest);
    }
    let Some((&head, rest)) = tail.split_first() else {
        bail!("git quoted path ends in a trailing backslash");
    };
    decoded.push(simple_escape(head)?);
    Ok(rest)
}

fn simple_escape(head: u8) -> Result<u8> {
    match head {
        b'a' => Ok(0x07),
        b'b' => Ok(0x08),
        b't' => Ok(b'\t'),
        b'n' => Ok(b'\n'),
        b'v' => Ok(0x0b),
        b'f' => Ok(0x0c),
        b'r' => Ok(b'\r'),
        b'"' => Ok(b'"'),
        b'\\' => Ok(b'\\'),
        other => bail!(
            "git quoted path carries an escape git does not write: \\{}",
            char::from(other)
        ),
    }
}

/// The byte a `\NNN` escape names. Git writes exactly three octal digits, so a
/// shorter run or a value past one byte is not an escape git could have
/// written and is left to [`simple_escape`] to reject.
fn octal_escape(tail: &[u8]) -> Option<(u8, &[u8])> {
    let digits = tail.get(..3)?;
    if !digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
        return None;
    }
    let value = digits
        .iter()
        .fold(0u16, |value, digit| value * 8 + u16::from(digit - b'0'));
    u8::try_from(value).ok().map(|byte| (byte, &tail[3..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unquoted_name_is_left_to_the_caller() {
        assert_eq!(take_quoted_path("a/demo.txt").unwrap(), None);
    }

    #[test]
    fn octal_escapes_decode_to_the_name_git_quoted() {
        let (name, rest) = take_quoted_path(r#""a/caf\303\251.txt" "b/caf\303\251.txt""#)
            .unwrap()
            .unwrap();

        assert_eq!(name, "a/café.txt");
        assert_eq!(rest, r#" "b/caf\303\251.txt""#);
    }

    #[test]
    fn single_letter_escapes_decode_to_their_bytes() {
        let (name, _) = take_quoted_path(r#""a/tab\there\\now\"quoted\".txt""#)
            .unwrap()
            .unwrap();

        assert_eq!(name, "a/tab\there\\now\"quoted\".txt");
    }

    #[test]
    fn malformed_quoting_is_refused_rather_than_half_decoded() {
        for malformed in [r#""a/unterminated.txt"#, r#""a/trailing\"#, r#""a/\q.txt""#] {
            assert!(
                take_quoted_path(malformed).is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn a_name_whose_bytes_are_not_utf8_is_refused() {
        assert!(take_quoted_path(r#""a/\377.txt""#).is_err());
    }
}
