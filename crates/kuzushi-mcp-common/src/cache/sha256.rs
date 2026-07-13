use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Read;

const HASH_BUFFER_BYTES: usize = 64 * 1024;

pub fn sha256_hex_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    digest_hex(hasher.finalize())
}

pub fn sha256_file_hex(path: &std::path::Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(digest_hex(hasher.finalize()))
}

fn digest_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut hex = String::with_capacity(64);
    for byte in bytes.as_ref() {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_hash_streams_multiple_chunks_and_matches_the_byte_digest() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let bytes = (0..HASH_BUFFER_BYTES * 3 + 17)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        std::fs::write(temp.path(), &bytes).unwrap();

        assert_eq!(
            sha256_file_hex(temp.path()).unwrap(),
            sha256_hex_bytes(&bytes)
        );
    }
}
