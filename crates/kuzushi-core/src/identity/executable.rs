//! The loaded executable binds cache/checkpoint semantics to code and dependencies.
use std::io::Read;

pub(crate) fn implementation_identity() -> Option<&'static str> {
    static IDENTITY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    IDENTITY.get_or_init(|| executable_digest().ok()).as_deref()
}

fn executable_digest() -> std::io::Result<String> {
    let mut file = std::fs::File::open(std::env::current_exe()?)?;
    let mut digest = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(digest.finalize().to_hex().to_string());
        }
        digest.update(&buffer[..count]);
    }
}
