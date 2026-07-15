use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

mod path_snapshot;

pub(super) use path_snapshot::PolicySnapshot;

const MAX_VERIFIED_POLICIES: usize = 64;
static VERIFIED_POLICIES: OnceLock<Mutex<VerifiedPolicyCache>> = OnceLock::new();

#[derive(Clone)]
struct CachedProof {
    policy: Vec<u8>,
    snapshot: PolicySnapshot,
}

#[derive(Default)]
struct VerifiedPolicyCache {
    entries: HashMap<PathBuf, CachedProof>,
    recency: VecDeque<PathBuf>,
}

pub(super) fn is_current(root: &Path, policy: &[u8]) -> Result<bool> {
    let Some(cached) = cached_proof(root) else {
        return Ok(false);
    };
    if cached.policy != policy {
        return Ok(false);
    }
    Ok(cached.snapshot == cached.snapshot.capture_current()?)
}

pub(super) fn capture(paths: impl IntoIterator<Item = PathBuf>) -> Result<PolicySnapshot> {
    PolicySnapshot::capture(paths)
}

pub(super) fn remember(root: &Path, policy: &[u8], snapshot: PolicySnapshot) {
    verified_policies()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            root.to_path_buf(),
            CachedProof {
                policy: policy.to_vec(),
                snapshot,
            },
        );
}

pub(super) fn remember_if_current(
    root: &Path,
    policy: &[u8],
    snapshot: PolicySnapshot,
) -> Result<bool> {
    if snapshot != snapshot.capture_current()? {
        return Ok(false);
    }
    remember(root, policy, snapshot);
    Ok(true)
}

impl VerifiedPolicyCache {
    fn get(&mut self, root: &Path) -> Option<CachedProof> {
        let cached = self.entries.get(root)?.clone();
        self.touch(root);
        Some(cached)
    }

    fn insert(&mut self, root: PathBuf, proof: CachedProof) {
        self.entries.insert(root.clone(), proof);
        self.touch(&root);
        self.evict_excess();
    }

    fn touch(&mut self, root: &Path) {
        self.recency.retain(|candidate| candidate != root);
        self.recency.push_back(root.to_path_buf());
    }

    fn evict_excess(&mut self) {
        while self.entries.len() > MAX_VERIFIED_POLICIES {
            let Some(oldest) = self.recency.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

fn cached_proof(root: &Path) -> Option<CachedProof> {
    verified_policies()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(root)
}

fn verified_policies() -> &'static Mutex<VerifiedPolicyCache> {
    VERIFIED_POLICIES.get_or_init(|| Mutex::new(VerifiedPolicyCache::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_the_least_recently_used_root_at_its_bound() {
        let mut cache = VerifiedPolicyCache::default();
        for index in 0..MAX_VERIFIED_POLICIES {
            cache.insert(root(index), proof(index));
        }
        assert!(cache.get(&root(0)).is_some());

        cache.insert(root(MAX_VERIFIED_POLICIES), proof(MAX_VERIFIED_POLICIES));

        assert_eq!(cache.entries.len(), MAX_VERIFIED_POLICIES);
        assert!(cache.entries.contains_key(&root(0)));
        assert!(!cache.entries.contains_key(&root(1)));
    }

    #[test]
    fn current_snapshot_is_verified_before_it_enters_the_cache() {
        let root = root(MAX_VERIFIED_POLICIES + 1);
        let snapshot = PolicySnapshot::capture(Vec::<PathBuf>::new()).unwrap();

        assert!(remember_if_current(&root, b"policy", snapshot).unwrap());
        assert!(is_current(&root, b"policy").unwrap());
    }

    fn root(index: usize) -> PathBuf {
        PathBuf::from(format!("/workspace-{index}"))
    }

    fn proof(index: usize) -> CachedProof {
        CachedProof {
            policy: vec![index as u8],
            snapshot: PolicySnapshot::empty_for_test(),
        }
    }
}
