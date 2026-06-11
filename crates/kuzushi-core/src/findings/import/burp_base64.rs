//! Minimal standard-base64 decoder for the Burp XML importer. We'd
//! rather inline a tiny parser than add a new crate just for the
//! request/response body field. Tolerates whitespace; errors on any
//! non-alphabet byte or pad in the middle of the input.
//!
//! Split into its own module so `burp_xml.rs` stays focused on XML
//! parsing and passes the CRAP-risk per-file gate.

use anyhow::Result;

pub(super) fn decode_base64_string(input: &str) -> Result<String> {
    let bytes = decode_base64_bytes(input.as_bytes())?;
    String::from_utf8(bytes).map_err(|err| anyhow::anyhow!("Burp XML body decoded to non-UTF-8: {err}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_standard_base64() {
        assert_eq!(
            decode_base64_string("SGVsbG8gd29ybGQ=").unwrap(),
            "Hello world"
        );
    }

    #[test]
    fn ignores_whitespace_in_input() {
        assert_eq!(
            decode_base64_string("SGVs\nbG8g\nd29ybGQ=").unwrap(),
            "Hello world"
        );
    }

    #[test]
    fn rejects_non_alphabet_bytes() {
        assert!(decode_base64_string("not_base64!").is_err());
    }

    #[test]
    fn rejects_payload_after_padding() {
        assert!(decode_base64_bytes(b"AB==CD").is_err());
    }
}
