use super::{
    UNTRUSTED_DERIVED_BEGIN, UNTRUSTED_DERIVED_END, UNTRUSTED_REPO_BEGIN, UNTRUSTED_REPO_END,
};
use std::fmt::Write as _;

const RECORD_VERSION_LINE: &str = "record_version=1";
const RECORD_ENCODING_LINE: &str = "encoding=percent-v1";
const MAX_LENGTH_DIGITS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UntrustedRecordKind {
    Repository,
    Derived,
}

impl UntrustedRecordKind {
    fn name(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Derived => "derived",
        }
    }

    fn markers(self) -> (&'static str, &'static str) {
        match self {
            Self::Repository => (UNTRUSTED_REPO_BEGIN, UNTRUSTED_REPO_END),
            Self::Derived => (UNTRUSTED_DERIVED_BEGIN, UNTRUSTED_DERIVED_END),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedRecord {
    pub kind: UntrustedRecordKind,
    pub label: String,
    pub content: String,
}

pub(super) fn render_record(kind: UntrustedRecordKind, label: &str, content: &str) -> String {
    let (begin, end) = kind.markers();
    format!(
        "{begin}\n{RECORD_VERSION_LINE}\nkind={kind}\n{RECORD_ENCODING_LINE}\nlabel_bytes={label_len}\ncontent_bytes={content_len}\nlabel={label}\ncontent={content}\n{end}",
        kind = kind.name(),
        label_len = label.len(),
        content_len = content.len(),
        label = encode_field(label),
        content = encode_field(content),
    )
}

pub fn decode_untrusted_record(frame: &str) -> Result<UntrustedRecord, String> {
    let mut lines = frame.split('\n');
    let begin = next_line(&mut lines, "begin marker")?;
    expect_line(&mut lines, RECORD_VERSION_LINE)?;
    let kind = parse_kind(next_field(&mut lines, "kind")?, begin)?;
    expect_line(&mut lines, RECORD_ENCODING_LINE)?;
    let label_len = parse_length(next_field(&mut lines, "label_bytes")?, "label_bytes")?;
    let content_len = parse_length(next_field(&mut lines, "content_bytes")?, "content_bytes")?;
    let label = decode_field(next_field(&mut lines, "label")?)?;
    let content = decode_field(next_field(&mut lines, "content")?)?;
    let end = next_line(&mut lines, "end marker")?;
    validate_frame_tail(&mut lines, kind, end)?;
    validate_length("label", label_len, label.len())?;
    validate_length("content", content_len, content.len())?;
    Ok(UntrustedRecord {
        kind,
        label,
        content,
    })
}

fn encode_field(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if safe_field_byte(byte) {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

fn decode_field(encoded: &str) -> Result<String, String> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            decoded.push(decode_escape(bytes, index)?);
            index += 3;
        } else if safe_field_byte(byte) {
            decoded.push(byte);
            index += 1;
        } else {
            return Err(format!(
                "record field contains non-canonical byte 0x{byte:02X}"
            ));
        }
    }
    String::from_utf8(decoded).map_err(|_| "record field is not valid UTF-8".to_string())
}

fn decode_escape(bytes: &[u8], index: usize) -> Result<u8, String> {
    let high = bytes
        .get(index + 1)
        .and_then(|byte| uppercase_hex(*byte))
        .ok_or_else(|| "record field has an invalid percent escape".to_string())?;
    let low = bytes
        .get(index + 2)
        .and_then(|byte| uppercase_hex(*byte))
        .ok_or_else(|| "record field has an invalid percent escape".to_string())?;
    let decoded = (high << 4) | low;
    if safe_field_byte(decoded) {
        return Err("record field has a non-canonical percent escape".to_string());
    }
    Ok(decoded)
}

fn uppercase_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn safe_field_byte(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) && !matches!(byte, b'%' | b'_')
}

fn next_line<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    label: &str,
) -> Result<&'a str, String> {
    lines
        .next()
        .ok_or_else(|| format!("untrusted record is missing {label}"))
}

fn expect_line<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    expected: &str,
) -> Result<(), String> {
    let actual = next_line(lines, expected)?;
    (actual == expected)
        .then_some(())
        .ok_or_else(|| format!("untrusted record expected {expected:?}, got {actual:?}"))
}

fn next_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &str,
) -> Result<&'a str, String> {
    let line = next_line(lines, name)?;
    line.strip_prefix(&format!("{name}="))
        .ok_or_else(|| format!("untrusted record is missing {name} field"))
}

fn parse_kind(value: &str, begin: &str) -> Result<UntrustedRecordKind, String> {
    match (value, begin) {
        ("repository", UNTRUSTED_REPO_BEGIN) => Ok(UntrustedRecordKind::Repository),
        ("derived", UNTRUSTED_DERIVED_BEGIN) => Ok(UntrustedRecordKind::Derived),
        _ => Err("untrusted record kind does not match its begin marker".to_string()),
    }
}

fn parse_length(value: &str, name: &str) -> Result<usize, String> {
    if value.is_empty() || value.len() > MAX_LENGTH_DIGITS {
        return Err(format!(
            "untrusted record {name} has an invalid byte-length width"
        ));
    }
    value
        .parse::<usize>()
        .map_err(|_| format!("untrusted record {name} is not a byte length"))
}

fn validate_frame_tail<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    kind: UntrustedRecordKind,
    end: &str,
) -> Result<(), String> {
    if end != kind.markers().1 {
        return Err("untrusted record end marker does not match its kind".to_string());
    }
    lines
        .next()
        .is_none()
        .then_some(())
        .ok_or_else(|| "untrusted record has trailing lines".to_string())
}

fn validate_length(name: &str, declared: usize, actual: usize) -> Result<(), String> {
    (declared == actual)
        .then_some(())
        .ok_or_else(|| format!("untrusted record {name} length is {actual}, expected {declared}"))
}
