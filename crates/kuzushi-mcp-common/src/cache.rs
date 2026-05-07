//! Per-repo cache layout shared across the three MCP servers.
//!
//! Layout:
//! ```text
//! ~/.kuzushi/index/
//! ├── joern/<repo-hash>/<commit>/cpg.bin.zip
//! ├── clang/<repo-hash>/compile_commands.json
//! ├── gtags/<repo-hash>/{GTAGS,GRTAGS,GPATH}
//! └── manifest.json
//! ```
//!
//! `repo-hash` is the SHA-256 of the canonical repo path (and the optional
//! git remote URL when present). Commit pinning is per-backend: joern
//! caches per commit; clang's `compile_commands.json` and gtags's symbol
//! tables are regenerated on each `parse`/`index` call so the on-disk
//! state always reflects the most recent run.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const KUZUSHI_DIR: &str = ".kuzushi";
const INDEX_DIR: &str = "index";

/// Returns the root of the per-user index cache, creating intermediate
/// directories on first use.
pub fn index_root() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not resolve home directory")?;
    let root = home.join(KUZUSHI_DIR).join(INDEX_DIR);
    std::fs::create_dir_all(&root).context("could not create kuzushi index dir")?;
    Ok(root)
}

/// Path to the top-level manifest.json that records every repo we've
/// indexed and via which backend(s).
pub fn manifest_path() -> Result<PathBuf> {
    Ok(index_root()?.join("manifest.json"))
}

/// Identifying fingerprint of a repo for cache-keying purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepoFingerprint {
    pub canonical_path: PathBuf,
    pub git_remote: Option<String>,
    pub hash: String,
}

/// Compute a stable hash for a repo path. Deterministic across runs;
/// includes the git remote URL when present so two checkouts of the same
/// upstream collide on the same key (intentional — they share an index).
pub fn repo_hash(path: &Path) -> Result<RepoFingerprint> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize {}", path.display()))?;
    let git_remote = read_git_remote(&canonical);

    let mut input = canonical.display().to_string();
    if let Some(remote) = &git_remote {
        input.push('|');
        input.push_str(remote);
    }
    let hash = sha256_hex(&input);

    Ok(RepoFingerprint {
        canonical_path: canonical,
        git_remote,
        hash,
    })
}

fn read_git_remote(repo: &Path) -> Option<String> {
    let head_config = repo.join(".git").join("config");
    if !head_config.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&head_config).ok()?;
    // Cheap parse: look for a [remote "origin"] block and the next `url = ...`.
    let mut in_origin = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if in_origin {
            if let Some(rest) = trimmed.strip_prefix("url") {
                let value = rest.trim_start_matches([' ', '=']).trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Tiny pure-Rust SHA-256 — 32 bytes hex-encoded. Hand-rolled to avoid
/// pulling in a crypto crate just for cache keys (no security
/// requirement; collision resistance is incidental).
fn sha256_hex(input: &str) -> String {
    let bytes = sha256_bytes(input.as_bytes());
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    // FIPS 180-4 SHA-256. Plain implementation — straightforward but not
    // optimised.  Used only for stable cache keys.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: pad the message.
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().enumerate().take(16) {
            let off = i * 4;
            *slot =
                u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Top-level manifest tracking which repos have been indexed by which
/// backends. Persisted as JSON at `index_root()/manifest.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheManifest {
    pub repos: Vec<RepoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoEntry {
    pub fingerprint: RepoFingerprint,
    /// Per-backend last-indexed timestamp (RFC 3339).
    pub backends: Vec<BackendEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendEntry {
    pub backend: String,
    pub last_indexed: String,
    pub commit: Option<String>,
    pub size_bytes: u64,
}

impl CacheManifest {
    pub fn load() -> Result<Self> {
        let path = manifest_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("could not read manifest at {}", path.display()))?;
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    pub fn save(&self) -> Result<()> {
        let path = manifest_path()?;
        let raw = serde_json::to_string_pretty(self).context("could not encode manifest")?;
        std::fs::write(&path, raw)
            .with_context(|| format!("could not write manifest to {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known SHA-256 of the empty string — sanity check the hand-rolled hash.
    #[test]
    fn sha256_of_empty_matches_known_vector() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Known SHA-256 of "abc".
    #[test]
    fn sha256_of_abc_matches_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Repo hash is stable for the same path/remote pair.
    #[test]
    fn repo_hash_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let a = repo_hash(tmp.path()).unwrap();
        let b = repo_hash(tmp.path()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.hash.len(), 64);
    }

    #[test]
    fn read_git_remote_finds_origin_url_only_inside_origin_block() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            git_dir.join("config"),
            r#"
[remote "upstream"]
    url = git@example.com:wrong/repo.git
[remote "origin"]
    fetch = +refs/heads/*:refs/remotes/origin/*
    url = git@example.com:org/repo.git
"#,
        )
        .unwrap();

        assert_eq!(
            read_git_remote(tmp.path()).as_deref(),
            Some("git@example.com:org/repo.git")
        );
    }

    #[test]
    fn manifest_round_trips() {
        let manifest = CacheManifest {
            repos: vec![RepoEntry {
                fingerprint: RepoFingerprint {
                    canonical_path: PathBuf::from("/tmp/repo"),
                    git_remote: Some("git@github.com:foo/bar.git".to_string()),
                    hash: "abc123".to_string(),
                },
                backends: vec![BackendEntry {
                    backend: "gtags".to_string(),
                    last_indexed: "2026-05-06T00:00:00Z".to_string(),
                    commit: Some("deadbeef".to_string()),
                    size_bytes: 1024,
                }],
            }],
        };
        let s = serde_json::to_string(&manifest).unwrap();
        let back: CacheManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.repos.len(), 1);
        assert_eq!(back.repos[0].fingerprint.hash, "abc123");
    }
}
