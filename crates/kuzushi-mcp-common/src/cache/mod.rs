mod fingerprint;
mod manifest;
mod paths;
mod sha256;

#[cfg(test)]
mod tests;

pub use fingerprint::{repo_hash, RepoFingerprint};
pub use manifest::{BackendEntry, CacheManifest, RepoEntry};
pub use paths::{index_root, manifest_path};
pub use sha256::{sha256_file_hex, sha256_hex_bytes};

#[cfg(test)]
pub(crate) use fingerprint::{read_git_remote, sha256_hex};
