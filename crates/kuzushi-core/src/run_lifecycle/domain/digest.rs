use sha2::{Digest, Sha256};

/// Content digest label shared by run-item envelope hashes and artifact
/// references: the `sha256:` prefix followed by lowercase hex.
pub fn sha256_content_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::sha256_content_digest;

    #[test]
    fn empty_input_matches_the_known_sha256_vector() {
        assert_eq!(
            sha256_content_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_zero_pads_low_bytes_in_the_full_32_byte_output() {
        // sha256("kuzushi") has 0x09 at index 1, pinning per-byte zero padding.
        assert_eq!(
            sha256_content_digest(b"kuzushi"),
            "sha256:37096f1d4fdb3089c66e4e22ba392f74d9b68c8503e1e4161a2add8aca093bf3"
        );
    }
}
