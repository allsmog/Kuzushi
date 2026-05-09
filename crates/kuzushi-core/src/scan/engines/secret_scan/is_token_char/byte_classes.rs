use super::*;

pub(in crate::scan::engines::secret_scan) fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b'+' | b'.')
}

pub(in crate::scan::engines::secret_scan) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

pub(in crate::scan::engines::secret_scan) fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

pub(in crate::scan::engines::secret_scan) fn is_alnum_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

pub(in crate::scan::engines::secret_scan) fn is_alnum_underscore_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

pub(in crate::scan::engines::secret_scan) fn is_base64_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'=')
}

pub(in crate::scan::engines::secret_scan) fn is_generic_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!@#$%^&*_+/=-".contains(&byte)
}

pub(in crate::scan::engines::secret_scan) fn skip_ascii_whitespace(
    bytes: &[u8],
    mut cursor: usize,
) -> usize {
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

pub(in crate::scan::engines::secret_scan) fn is_binary_extension(
    path: &Path,
    binary_exts: &BTreeSet<String>,
) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .is_some_and(|ext| binary_exts.contains(ext.as_str()))
}

pub(in crate::scan::engines::secret_scan) fn is_likely_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(4096).any(|byte| *byte == 0)
}
