use serde::{Deserialize, Serialize};

/// A pair of (allocation function, free function) that bound an object's
/// lifetime in the target codebase. The agent uses these as anchors to
/// hunt for use-after-free / double-free patterns: walk callees from a
/// site that returns the allocator's value, then look for any reachable
/// path where a freed pointer is dereferenced again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocFreePair {
    pub alloc: String,
    pub free: String,
}

impl AllocFreePair {
    pub fn new(alloc: impl Into<String>, free: impl Into<String>) -> Self {
        Self {
            alloc: alloc.into(),
            free: free.into(),
        }
    }
}

/// Codebase-agnostic baseline. Operators extend this with project-specific
/// pairs (e.g. `zmalloc`/`zfree`, `sdsnew`/`sdsfree` for Redis) via the
/// `allocFreePairs` or `extraAllocFreePairs` input fields.
pub fn default_alloc_free_pairs() -> Vec<AllocFreePair> {
    vec![
        AllocFreePair::new("malloc", "free"),
        AllocFreePair::new("calloc", "free"),
        AllocFreePair::new("realloc", "free"),
        AllocFreePair::new("strdup", "free"),
        AllocFreePair::new("strndup", "free"),
    ]
}
