//! Decoding and disclosure for capture payload fields.
//!
//! Burp XML marks a request/response with `base64="true"` and HAR marks a
//! body with `encoding = "base64"` exactly when the payload is binary or
//! compressed. Such a payload is not text, so the importers must say how the
//! blob they store relates to what the capture held instead of presenting an
//! encoded or lossily decoded payload as the raw HTTP message.
//!
//! The base64 decoder is inlined rather than pulled from a crate: it is a
//! tiny parser, tolerates whitespace, and errors on any non-alphabet byte or
//! pad in the middle of the input.

use anyhow::Result;

/// One capture field after decoding, with the disclosure an operator needs to
/// read the stored blob honestly. `note` is `None` only when the stored text
/// is exactly what the capture carried.
pub(super) struct DecodedField {
    pub(super) text: String,
    pub(super) note: Option<&'static str>,
}

/// Decode a field the capture declared as base64.
///
/// A payload that is not valid UTF-8 is kept, with its undecodable bytes
/// replaced, because the readable part is still evidence. A field that does
/// not decode at all keeps its literal text: the importer cannot know whether
/// the producer mislabeled the encoding or truncated the payload.
pub(super) fn decode_base64_field(raw: &str) -> DecodedField {
    let Ok(bytes) = decode_base64_bytes(raw.trim().as_bytes()) else {
        return DecodedField {
            text: raw.to_string(),
            note: Some("was declared base64 but did not decode; the encoded field text is preserved verbatim"),
        };
    };
    match String::from_utf8(bytes) {
        Ok(text) => DecodedField { text, note: None },
        Err(err) => DecodedField {
            text: String::from_utf8_lossy(err.as_bytes()).into_owned(),
            note: Some("is binary or not valid UTF-8; undecodable bytes are shown as U+FFFD"),
        },
    }
}

/// Name the field a decode note is about, so one rationale can carry a note
/// for the request and another for the response.
pub(super) fn disclosure(label: &str, decoded: &DecodedField) -> Option<String> {
    decoded.note.map(|note| format!("The {label} {note}"))
}

/// Compose the evidence rationale from the importer's provenance line and
/// whatever disclosures the fields produced.
pub(super) fn rationale_with(provenance: &str, notes: &[String]) -> String {
    let mut rationale = String::from(provenance);
    for note in notes {
        rationale.push_str(". ");
        rationale.push_str(note);
    }
    rationale
}

pub(super) fn decode_base64_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut state = Base64State::default();
    for &byte in input {
        accumulate_base64_byte(byte, &mut state, &mut out)?;
    }
    Ok(out)
}

#[derive(Default)]
struct Base64State {
    buf: u32,
    bits: u8,
    padding: u8,
}

fn accumulate_base64_byte(byte: u8, state: &mut Base64State, out: &mut Vec<u8>) -> Result<()> {
    if byte.is_ascii_whitespace() {
        return Ok(());
    }
    if byte == b'=' {
        state.padding += 1;
        return Ok(());
    }
    let value = base64_alphabet_value(byte, state.padding)?;
    feed_base64_state(state, value, out);
    Ok(())
}

fn feed_base64_state(state: &mut Base64State, value: u8, out: &mut Vec<u8>) {
    state.buf = (state.buf << 6) | (value as u32);
    state.bits += 6;
    if state.bits >= 8 {
        state.bits -= 8;
        out.push(((state.buf >> state.bits) & 0xFF) as u8);
    }
}

fn base64_alphabet_value(byte: u8, padding: u8) -> Result<u8> {
    if padding > 0 {
        anyhow::bail!("invalid base64: non-pad after padding");
    }
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => anyhow::bail!("invalid base64 character"),
    }
}

/// Standard base64 encoder for the importer tests, so a fixture can carry the
/// exact bytes a capture would have encoded.
#[cfg(test)]
pub(super) fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let len = chunk.len();
        let b1 = if len > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if len > 2 { chunk[2] as u32 } else { 0 };
        let triple = ((chunk[0] as u32) << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(base64_tail(len > 1, (triple >> 6) & 0x3F));
        out.push(base64_tail(len > 2, triple & 0x3F));
    }
    out
}

#[cfg(test)]
fn base64_tail(present: bool, value: u32) -> char {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if present {
        ALPHABET[value as usize] as char
    } else {
        '='
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_base64_without_a_note() {
        let decoded = decode_base64_field("SGVsbG8gd29ybGQ=");

        assert_eq!(decoded.text, "Hello world");
        assert!(decoded.note.is_none());
    }

    #[test]
    fn ignores_whitespace_in_input() {
        assert_eq!(decode_base64_field("SGVs\nbG8g\nd29ybGQ=").text, "Hello world");
    }

    #[test]
    fn encoder_helper_round_trips_through_the_decoder() {
        for payload in [&b"a"[..], b"ab", b"abc", b"abcd", &[0x00, 0xFF, 0x10]] {
            assert_eq!(
                decode_base64_bytes(encode_base64(payload).as_bytes()).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn non_utf8_payload_is_disclosed_rather_than_silently_replaced() {
        // 0xFF cannot start a UTF-8 sequence; the readable bytes survive.
        let decoded = decode_base64_field(&encode_base64(b"HTTP/1.1 200 OK\r\n\r\n\xFF\xD8\xFF"));

        assert!(decoded.text.starts_with("HTTP/1.1 200 OK"));
        assert!(decoded.text.contains('\u{FFFD}'));
        assert_eq!(
            disclosure("response", &decoded).as_deref(),
            Some("The response is binary or not valid UTF-8; undecodable bytes are shown as U+FFFD")
        );
    }

    #[test]
    fn undecodable_field_keeps_its_text_and_says_so() {
        let decoded = decode_base64_field("not_base64!");

        assert_eq!(decoded.text, "not_base64!");
        assert_eq!(
            disclosure("request", &decoded).as_deref(),
            Some(
                "The request was declared base64 but did not decode; \
                 the encoded field text is preserved verbatim"
            )
        );
    }

    #[test]
    fn rejects_payload_after_padding() {
        assert!(decode_base64_bytes(b"AB==CD").is_err());
    }

    #[test]
    fn rationale_appends_every_disclosure_after_the_provenance() {
        let notes = vec!["The request is odd".to_string(), "The response is odd".to_string()];

        assert_eq!(
            rationale_with("Imported", &notes),
            "Imported. The request is odd. The response is odd"
        );
    }
}
