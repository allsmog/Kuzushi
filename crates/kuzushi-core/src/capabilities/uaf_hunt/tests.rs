use super::adapters::{parse_uaf_hunt_input, resolve_compile_commands_path};
use serde_json::json;
use tempfile::tempdir;

#[test]
fn defaults_include_malloc_calloc_realloc_strdup_strndup() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({});
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();

    let allocs: Vec<&str> = options
        .alloc_free_pairs
        .iter()
        .map(|pair| pair.alloc.as_str())
        .collect();
    assert!(allocs.contains(&"malloc"));
    assert!(allocs.contains(&"calloc"));
    assert!(allocs.contains(&"realloc"));
    assert!(allocs.contains(&"strdup"));
    assert!(allocs.contains(&"strndup"));
    let frees: Vec<&str> = options
        .alloc_free_pairs
        .iter()
        .map(|pair| pair.free.as_str())
        .collect();
    assert!(frees.iter().all(|free| *free == "free"));
}

#[test]
fn extra_alloc_free_pairs_extend_defaults_without_duplicating() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({
        "extraAllocFreePairs": [
            {"alloc": "zmalloc", "free": "zfree"},
            {"alloc": "sdsnewlen", "free": "sdsfree"},
            // Already in defaults — should not duplicate.
            {"alloc": "malloc", "free": "free"},
        ]
    });
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();
    let zmalloc_count = options
        .alloc_free_pairs
        .iter()
        .filter(|pair| pair.alloc == "zmalloc")
        .count();
    let malloc_count = options
        .alloc_free_pairs
        .iter()
        .filter(|pair| pair.alloc == "malloc")
        .count();
    assert_eq!(zmalloc_count, 1);
    assert_eq!(malloc_count, 1, "default malloc pair was duplicated");
    assert!(options
        .alloc_free_pairs
        .iter()
        .any(|pair| pair.alloc == "sdsnewlen" && pair.free == "sdsfree"));
}

#[test]
fn alloc_free_pairs_replaces_defaults_entirely() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let input = json!({
        "allocFreePairs": [
            {"alloc": "zmalloc", "free": "zfree"},
        ]
    });
    let options = parse_uaf_hunt_input(&input, dir.path()).unwrap();
    assert_eq!(options.alloc_free_pairs.len(), 1);
    assert_eq!(options.alloc_free_pairs[0].alloc, "zmalloc");
}

#[test]
fn empty_alloc_free_pairs_array_bails_with_helpful_message() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("compile_commands.json"), "[]").unwrap();

    let err = parse_uaf_hunt_input(&json!({"allocFreePairs": []}), dir.path()).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("allocFreePairs"),
        "missing field name in bail: {message}"
    );
    assert!(
        message.contains("defaults") || message.contains("default"),
        "no hint about removing the key to use defaults: {message}"
    );
}

#[test]
fn missing_compile_commands_json_bails_loudly() {
    let dir = tempdir().unwrap();
    let err = resolve_compile_commands_path(&json!({}), dir.path()).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("compile_commands.json"),
        "bail must name the missing file: {message}"
    );
    assert!(
        message.contains("bear") || message.contains("CMAKE_EXPORT_COMPILE_COMMANDS"),
        "bail must suggest a generator command: {message}"
    );
}

#[test]
fn compile_commands_found_under_build_subdir() {
    let dir = tempdir().unwrap();
    let build_dir = dir.path().join("build");
    std::fs::create_dir(&build_dir).unwrap();
    std::fs::write(build_dir.join("compile_commands.json"), "[]").unwrap();

    let resolved = resolve_compile_commands_path(&json!({}), dir.path()).unwrap();
    assert_eq!(resolved, build_dir.join("compile_commands.json"));
}

#[test]
fn explicit_compile_commands_path_honored() {
    let dir = tempdir().unwrap();
    let custom = dir.path().join("custom-cc.json");
    std::fs::write(&custom, "[]").unwrap();

    let resolved = resolve_compile_commands_path(
        &json!({"compileCommandsPath": custom.display().to_string()}),
        dir.path(),
    )
    .unwrap();
    assert_eq!(resolved, custom);
}
