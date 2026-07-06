use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blake3Hash(String);

impl Blake3Hash {
    pub fn new(value: String) -> anyhow::Result<Self> {
        if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("invalid BLAKE3 hex hash");
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn hash_parts(domain: &str, parts: &[&[u8]]) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    update_part(&mut hasher, b"kuzushi:v3");
    update_part(&mut hasher, domain.as_bytes());
    for part in parts {
        update_part(&mut hasher, part);
    }
    Blake3Hash(hasher.finalize().to_hex().to_string())
}

fn update_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_changes_hashes_for_same_bytes() {
        let blob = hash_parts("object:blob", &[b"same"]);
        let event = hash_parts("event", &[b"same"]);

        assert_ne!(blob, event);
    }

    #[test]
    fn length_prefix_prevents_boundary_ambiguity() {
        let first = hash_parts("demo", &[b"ab", b"c"]);
        let second = hash_parts("demo", &[b"a", b"bc"]);

        assert_ne!(first, second);
    }
}
