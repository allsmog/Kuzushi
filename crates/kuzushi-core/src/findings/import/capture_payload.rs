//! Decoding and disclosure for capture payload fields.
//!
//! Burp XML marks a request/response with `base64="true"` and HAR marks a
//! body with `encoding = "base64"` exactly when the payload is binary or
//! compressed. Such a payload is not text, so the importers must say how the
//! blob they store relates to what the capture held instead of presenting an
//! encoded or lossily decoded payload as the raw HTTP message.
//!
//! Decoding is strict on purpose. A field that is truncated, non-canonical,
//! or not base64 at all must fail here rather than decode to a body that is
//! silently shorter than the capture's: the caller answers a failure by
//! preserving the field verbatim and disclosing it.

use anyhow::Result;
use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD};
use base64::Engine as _;

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
    let Ok(bytes) = decode_base64_bytes(raw) else {
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

/// Standard base64, tolerating only the line wrapping a capture may have
/// added around it.
///
/// Both engines reject a truncated field: a final quantum of one symbol
/// cannot exist, and neither accepts non-canonical trailing bits. That is the
/// whole point of decoding here — `"A"` must not become an empty body, and
/// `"AAAAA"` must not quietly lose its last symbol. Padded and unpadded input
/// are both accepted because captures come from more than one encoder, but
/// each form is decoded strictly.
pub(super) fn decode_base64_bytes(raw: &str) -> Result<Vec<u8>> {
    let compact: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    BASE64
        .decode(&compact)
        .or_else(|_| BASE64_NO_PAD.decode(&compact))
        .map_err(|err| anyhow::anyhow!("invalid base64: {err}"))
}

/// Standard base64 encoder for the importer tests, so a fixture can carry the
/// exact bytes a capture would have encoded.
#[cfg(test)]
pub(super) fn encode_base64(input: &[u8]) -> String {
    BASE64.encode(input)
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
                decode_base64_bytes(&encode_base64(payload)).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn a_truncated_quantum_does_not_decode_to_a_shortened_body() {
        // "A" carries no complete byte and "AAAAA" ends mid-quantum: a lax
        // decoder answers both with a body shorter than the capture's, and
        // that body is valid UTF-8, so no disclosure would ever fire.
        for truncated in ["A", "AAAAA"] {
            let decoded = decode_base64_field(truncated);

            assert_eq!(decoded.text, truncated);
            assert!(
                decoded.note.is_some(),
                "{truncated:?} must be disclosed, not silently shortened"
            );
        }
    }

    #[test]
    fn unpadded_canonical_base64_still_decodes() {
        let decoded = decode_base64_field("SGVsbG8gd29ybGQ");

        assert_eq!(decoded.text, "Hello world");
        assert!(decoded.note.is_none());
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
        assert!(decode_base64_bytes("AB==CD").is_err());
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
