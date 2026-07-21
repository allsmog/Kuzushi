use super::*;
use serde_json::json;

fn entry(value: serde_json::Value) -> SemanticCacheEntry {
    SemanticCacheEntry {
        task: "full-mode-multi:chunk".to_string(),
        model: "claude-haiku-4-5".to_string(),
        created_at_ms: 1,
        source_cost_usd: 0.42,
        value,
    }
}

#[test]
fn round_trips_an_entry_by_key() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let key = structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({"type": "array"}));

    assert_eq!(cache.get(&key), None);
    cache.put(&key, &entry(json!([{"file": "a.c"}]))).unwrap();

    let hit = cache.get(&key).expect("stored entry must be readable");
    assert_eq!(hit.value, json!([{"file": "a.c"}]));
    assert_eq!(hit.source_cost_usd, 0.42);
}

#[test]
fn every_key_ingredient_changes_the_key() {
    let schema = json!({"type": "array"});
    let base = structured_query_cache_key("m", "sys", "prompt", "Schema", &schema);
    let variants = [
        structured_query_cache_key("m2", "sys", "prompt", "Schema", &schema),
        structured_query_cache_key("m", "sys2", "prompt", "Schema", &schema),
        structured_query_cache_key("m", "sys", "prompt2", "Schema", &schema),
        structured_query_cache_key("m", "sys", "prompt", "Schema2", &schema),
        structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({"type": "object"})),
    ];
    for variant in variants {
        assert_ne!(base, variant, "changed ingredient must change the key");
    }
}

#[test]
fn corrupt_entries_read_as_misses() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let key = structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({}));
    cache.put(&key, &entry(json!(1))).unwrap();
    std::fs::write(cache.entry_path(&key), b"not json").unwrap();

    assert_eq!(cache.get(&key), None);
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_cache_root() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let linked = tmp.path().join("linked-cache");
    symlink(outside.path(), &linked).unwrap();

    assert!(SemanticCache::open_at(&linked).is_err());
}

#[cfg(unix)]
#[test]
fn put_refuses_a_symlinked_shard_directory() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let key = structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({}));
    let shard = cache.entry_path(&key).parent().unwrap().to_path_buf();
    symlink(outside.path(), &shard).unwrap();

    assert!(cache.put(&key, &entry(json!(1))).is_err());
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[test]
fn retention_pass_drops_stale_entries_and_keeps_fresh_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let stale_key = structured_query_cache_key("m", "sys", "old", "Schema", &json!({}));
    let fresh_key = structured_query_cache_key("m", "sys", "new", "Schema", &json!({}));
    cache.put(&stale_key, &entry(json!("stale"))).unwrap();
    cache
        .put(
            &fresh_key,
            &cache_entry_now("full-mode-multi:chunk", "m", 0.1, json!("fresh")),
        )
        .unwrap();

    cache.prune_entries_older_than(1_000);

    assert_eq!(cache.get(&stale_key), None);
    assert!(cache.get(&fresh_key).is_some());
    assert!(!cache.entry_path(&stale_key).parent().unwrap().exists());
}

#[test]
fn retention_pass_drops_corrupt_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let key = structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({}));
    cache
        .put(
            &key,
            &cache_entry_now("full-mode-multi:chunk", "m", 0.1, json!("fresh")),
        )
        .unwrap();
    std::fs::write(cache.entry_path(&key), b"not json").unwrap();

    // Cutoff 0 keeps every dated entry — only corruption is dropped.
    cache.prune_entries_older_than(0);

    assert!(!cache.entry_path(&key).exists());
}

#[test]
fn open_for_target_prunes_at_most_once_a_day() {
    let tmp = tempfile::tempdir().unwrap();
    let _lock = crate::test_env::semantic_cache_env_lock();
    let stale_key = structured_query_cache_key("m", "sys", "old", "Schema", &json!({}));
    let stamp = crate::workspace::workspace_state_dir(tmp.path())
        .join(SEMANTIC_CACHE_DIR)
        .join("last-prune-at-ms");

    let cache = SemanticCache::open_for_target(tmp.path()).expect("cache should open");
    assert!(stamp.is_file(), "first open must record a prune stamp");
    cache.put(&stale_key, &entry(json!("stale"))).unwrap();

    let cache = SemanticCache::open_for_target(tmp.path()).expect("cache should reopen");
    assert!(
        cache.get(&stale_key).is_some(),
        "a same-day reopen must not walk the store again"
    );

    std::fs::remove_file(&stamp).unwrap();
    let cache = SemanticCache::open_for_target(tmp.path()).expect("cache should reopen");
    assert_eq!(
        cache.get(&stale_key),
        None,
        "a due retention pass must drop entries past the retention window"
    );
}

#[test]
fn open_for_target_respects_the_env_kill_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let _lock = crate::test_env::semantic_cache_env_lock();
    let _guard = crate::test_env::ScopedEnv::set(SEMANTIC_CACHE_ENV, "off");

    assert!(SemanticCache::open_for_target(tmp.path()).is_none());
}

#[test]
fn open_for_target_lands_under_the_workspace_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let _lock = crate::test_env::semantic_cache_env_lock();
    let cache = SemanticCache::open_for_target(tmp.path()).expect("cache should open");
    let key = structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({}));
    cache.put(&key, &entry(json!(1))).unwrap();

    let expected_root = crate::workspace::workspace_state_dir(tmp.path()).join(SEMANTIC_CACHE_DIR);
    assert!(cache.entry_path(&key).starts_with(&expected_root));
    assert!(cache.entry_path(&key).is_file());
}
