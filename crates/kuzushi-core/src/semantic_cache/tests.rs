use super::*;

#[cfg(any(unix, windows))]
#[test]
fn hard_linked_database_and_journal_cannot_modify_operator_files() {
    for name in [database::DATABASE_FILE.to_string(), format!("{}-journal", database::DATABASE_FILE)] {
        let root = tempfile::tempdir().unwrap();
        let operator = root.path().join("operator.sqlite");
        let connection = rusqlite::Connection::open(&operator).unwrap();
        connection.execute_batch("CREATE TABLE private_data(value TEXT);").unwrap();
        drop(connection);
        let before = std::fs::read(&operator).unwrap();
        let cache = root.path().join("cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::hard_link(&operator, cache.join(name)).unwrap();
        assert!(SemanticCache::open_at(&cache).is_err());
        assert_eq!(std::fs::read(&operator).unwrap(), before);
    }
}
use serde_json::json;

fn entry(value: serde_json::Value) -> SemanticCacheEntry {
    cache_entry_now("full-mode-multi:chunk", "test-model", 0.42, value)
}

fn key(id: u32) -> Blake3Hash {
    hash_parts("cache-test", &[&id.to_be_bytes()])
}

#[test]
fn round_trips_an_entry_by_key() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    assert_eq!(cache.get(&key(0)), None);
    cache
        .put(&key(0), &entry(json!([{"file": "a.c"}])))
        .unwrap();
    let hit = cache.get(&key(0)).unwrap();
    assert_eq!(hit.value, json!([{"file": "a.c"}]));
    assert_eq!(hit.source_cost_usd, 0.42);
}

#[cfg(unix)]
#[test]
fn host_parent_aliases_work_without_accepting_linked_cache_roots() {
    let host = tempfile::tempdir().unwrap();
    let cache_root = host.path().join("state/cache");
    std::fs::create_dir_all(&cache_root).unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("host");
    std::os::unix::fs::symlink(host.path(), &alias).unwrap();

    let cache = SemanticCache::open_at(alias.join("state/cache")).unwrap();
    cache.put(&key(0), &entry(json!(1))).unwrap();
    assert_eq!(cache.get(&key(0)).unwrap().value, json!(1));

    let linked_root = aliases.path().join("linked-cache");
    std::os::unix::fs::symlink(&cache_root, &linked_root).unwrap();
    assert!(SemanticCache::open_at(&linked_root).is_err());
}

#[test]
fn every_legacy_key_ingredient_changes_the_key() {
    let schema = json!({"type": "array"});
    let base = structured_query_cache_key("m", "sys", "prompt", "Schema", &schema);
    let variants = [
        structured_query_cache_key("m2", "sys", "prompt", "Schema", &schema),
        structured_query_cache_key("m", "sys2", "prompt", "Schema", &schema),
        structured_query_cache_key("m", "sys", "prompt2", "Schema", &schema),
        structured_query_cache_key("m", "sys", "prompt", "Schema2", &schema),
        structured_query_cache_key("m", "sys", "prompt", "Schema", &json!({})),
    ];
    for variant in variants {
        assert_ne!(base, variant);
    }
}

#[test]
fn corrupt_entries_read_as_misses() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    cache.put(&key(0), &entry(json!(1))).unwrap();
    cache
        .connection()
        .unwrap()
        .execute("UPDATE entries SET body=x'ff'", [])
        .unwrap();
    assert_eq!(cache.get(&key(0)), None);
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_cache_root_and_database() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), tmp.path().join("linked")).unwrap();
    assert!(SemanticCache::open_at(tmp.path().join("linked")).is_err());
    let foreign = outside.path().join("foreign");
    fs::write(&foreign, "preserve").unwrap();
    symlink(&foreign, tmp.path().join(database::DATABASE_FILE)).unwrap();
    assert!(SemanticCache::open_at(tmp.path()).is_err());
    assert_eq!(fs::read_to_string(foreign).unwrap(), "preserve");
}

#[cfg(unix)]
#[test]
fn legacy_cleanup_refuses_symlinked_shards_without_touching_outside_entries() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let foreign = outside.path().join(format!("{}.json", key(1)));
    fs::write(&foreign, "preserve").unwrap();
    symlink(outside.path(), tmp.path().join("00")).unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    assert!(cache.maintain().is_err());
    assert_eq!(fs::read_to_string(foreign).unwrap(), "preserve");
}

#[test]
fn expired_entries_never_replay_and_open_evicts_only_one_indexed_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let mut stale = entry(json!("old"));
    stale.created_at_ms = 1;
    for id in 0..150 {
        cache.put(&key(id), &stale).unwrap();
    }
    assert_eq!(cache.get(&key(0)), None);
    drop(cache);
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    assert_eq!(
        database::totals(&cache.connection().unwrap()).unwrap().0,
        86
    );
    let report = cache.maintain().unwrap();
    assert_eq!(report.entries, 22);
    assert!(report.pending);
    assert!(report.reclaimed_payload_bytes > 0);
    let report = cache.maintain().unwrap();
    assert_eq!(report.entries, 0);
    assert!(!report.pending);
}

#[test]
fn concurrent_connections_enforce_entry_and_disk_quotas() {
    let tmp = tempfile::tempdir().unwrap();
    let limits = SemanticCacheLimits {
        max_bytes: 128 * 1024,
        max_entries: 5,
    };
    let left = SemanticCache::open_at_with_limits(tmp.path(), limits).unwrap();
    let right = SemanticCache::open_at_with_limits(tmp.path(), limits).unwrap();
    std::thread::scope(|scope| {
        for (cache, start) in [(&left, 0), (&right, 100)] {
            scope.spawn(move || {
                for id in start..start + 50 {
                    cache
                        .put(&key(id), &entry(json!("x".repeat(8 * 1024))))
                        .unwrap();
                    assert!(database::totals(&cache.connection().unwrap()).unwrap().0 <= 5);
                }
            });
        }
    });
    let report = left.maintain().unwrap();
    assert_eq!(report.entries, 5);
    assert!(report.quota_pressure);
    assert!(report.payload_bytes <= limits.max_bytes / 2);
    assert!(
        fs::metadata(tmp.path().join(database::DATABASE_FILE))
            .unwrap()
            .len()
            <= limits.max_bytes
    );
}

#[test]
fn oversized_serialization_never_creates_an_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    assert!(cache
        .put(
            &key(0),
            &entry(json!("x".repeat(MAX_SEMANTIC_CACHE_ENTRY_BYTES)))
        )
        .is_err());
    assert_eq!(
        database::totals(&cache.connection().unwrap()).unwrap(),
        (0, 0)
    );
}

#[test]
fn interrupted_legacy_cleanup_resumes_without_a_daily_delay() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    let shard = tmp.path().join("00");
    fs::create_dir(&shard).unwrap();
    for id in 0..100 {
        fs::write(shard.join(format!("{id:064x}.json")), "legacy").unwrap();
    }
    cache
        .connection()
        .unwrap()
        .execute("UPDATE cache_state SET legacy_shard=0,last_prune_ms=0", [])
        .unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "semantic_cache::tests::crash_during_legacy_prune_child",
            "--nocapture",
        ])
        .env("KUZUSHI_CACHE_CRASH_TEST_ROOT", tmp.path())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(27));
    assert_eq!(fs::read_dir(&shard).unwrap().count(), 37);
    assert_eq!(
        cache
            .connection()
            .unwrap()
            .query_row("SELECT last_prune_ms FROM cache_state", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(cache);
    let cache = SemanticCache::open_at(tmp.path()).unwrap();
    assert!(!shard.exists());
    while cache.maintain().unwrap().pending {}
    assert!(
        cache
            .connection()
            .unwrap()
            .query_row("SELECT last_prune_ms FROM cache_state", [], |r| r
                .get::<_, i64>(0))
            .unwrap()
            > 0
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
    let cache = SemanticCache::open_for_target(tmp.path()).unwrap();
    cache.put(&key(0), &entry(json!(1))).unwrap();
    let root = crate::workspace::workspace_state_dir(tmp.path()).join(SEMANTIC_CACHE_DIR);
    assert!(root.join(database::DATABASE_FILE).is_file());
}

#[test]
fn crash_during_legacy_prune_child() {
    let Some(root) = std::env::var_os("KUZUSHI_CACHE_CRASH_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root).canonicalize().unwrap();
    let mut connection = database::open(&root, SemanticCacheLimits::default()).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let (_, pending) = legacy_cleanup::prune_batch(&root, &transaction).unwrap();
    assert!(pending);
    // Exit without destructors or transaction commit, as on process death.
    std::process::exit(27);
}
