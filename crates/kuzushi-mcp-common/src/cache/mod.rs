mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
/// Returns the root of the per-user index cache, creating intermediate
/// directories on first use.

/// Path to the top-level manifest.json that records every repo we've
/// indexed and via which backend(s).

/// Identifying fingerprint of a repo for cache-keying purposes.

/// Compute a stable hash for a repo path. Deterministic across runs;
/// includes the git remote URL when present so two checkouts of the same
/// upstream collide on the same key (intentional — they share an index).

/// Tiny pure-Rust SHA-256 — 32 bytes hex-encoded. Hand-rolled to avoid
/// pulling in a crypto crate just for cache keys (no security
/// requirement; collision resistance is incidental).

/// Top-level manifest tracking which repos have been indexed by which
/// backends. Persisted as JSON at `index_root()/manifest.json`.

#[cfg(test)]
mod tests;

pub use items_1::index_root;
pub use items_1::manifest_path;
pub use items_1::repo_hash;
pub use items_1::RepoFingerprint;
pub use items_2::BackendEntry;
pub use items_2::CacheManifest;
pub use items_2::RepoEntry;
