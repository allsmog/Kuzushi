use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};

const CACHE_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct CacheKey {
    source_snapshot: String,
    request_hash: String,
    runtime_identity: String,
}

#[derive(Default)]
struct RuntimeCache {
    entries: BTreeMap<CacheKey, TriageOutcome>,
    order: VecDeque<CacheKey>,
}

impl RuntimeCache {
    fn get(&self, key: &CacheKey) -> Option<TriageOutcome> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: CacheKey, outcome: TriageOutcome) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, outcome);
        self.evict_oldest();
    }

    fn evict_oldest(&mut self) {
        while self.entries.len() > CACHE_CAPACITY {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn discard_source(&mut self, source: &str) {
        self.entries.retain(|key, _| key.source_snapshot != source);
        self.order.retain(|key| key.source_snapshot != source);
    }
}

static CACHE: OnceLock<Mutex<RuntimeCache>> = OnceLock::new();

pub(super) fn key(
    request: &TriageRequest,
    source_snapshot: Option<&str>,
    runtime_identity: Option<crate::identity::Blake3Hash>,
) -> Result<Option<CacheKey>> {
    let Some(source_snapshot) = source_snapshot else {
        return Ok(None);
    };
    let Some(runtime_identity) = runtime_identity else {
        return Ok(None);
    };
    let bytes = serde_json::to_vec(request)?;
    Ok(Some(CacheKey {
        source_snapshot: source_snapshot.to_string(),
        request_hash: blake3::hash(&bytes).to_hex().to_string(),
        runtime_identity: runtime_identity.as_str().to_string(),
    }))
}

pub(super) fn reusable_outcome(key: Option<&CacheKey>, retriage: bool) -> Option<TriageOutcome> {
    if retriage {
        return None;
    }
    let key = key?;
    let cache = CACHE.get_or_init(|| Mutex::new(RuntimeCache::default()));
    cache
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .get(key)
}

pub(super) fn remember(key: Option<CacheKey>, outcome: TriageOutcome) {
    let Some(key) = key else {
        return;
    };
    let cache = CACHE.get_or_init(|| Mutex::new(RuntimeCache::default()));
    cache
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .insert(key, outcome);
}

pub(super) fn discard_unverified_run(source: &str, result: &Result<Value>) {
    if result
        .as_ref()
        .is_ok_and(|value| value["status"] == "completed")
    {
        return;
    }
    let cache = CACHE.get_or_init(|| Mutex::new(RuntimeCache::default()));
    cache
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .discard_source(source);
}

#[cfg(test)]
mod tests;
