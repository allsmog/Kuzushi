use super::*;
use serde_json::json;

fn capture(root: &Path, text: &[u8]) -> Result<CompileDatabaseSnapshot> {
    let source = root.join("chosen.json");
    std::fs::write(&source, text)?;
    CompileDatabaseSnapshot::capture(&ReadRootCapability::new([root.to_path_buf()])?, &source)
}

#[test]
fn captures_exact_source_identity_and_binds_relative_working_directories() {
    let root = tempfile::tempdir().unwrap();
    let raw = serde_json::to_vec(&json!([{"directory":".","file":"owned café.c","arguments":["clang","-DCHOSEN=1","-c","owned café.c"],"output":"owned.o"}])).unwrap();
    let snapshot = capture(root.path(), &raw).unwrap();
    let prepared = std::fs::read(snapshot.path()).unwrap();
    let data: serde_json::Value = serde_json::from_slice(&prepared).unwrap();
    let receipt = snapshot.receipt();
    assert_eq!(receipt.source_sha256, sha256_hex_bytes(&raw));
    assert_eq!(receipt.prepared_sha256, sha256_hex_bytes(&prepared));
    assert_eq!(receipt.source_bytes, raw.len());
    assert_eq!(receipt.prepared_bytes, prepared.len());
    assert_eq!(receipt.entries, 1);
    assert!(Path::new(data[0]["directory"].as_str().unwrap()).is_absolute());
    assert_eq!(data[0]["file"], "owned café.c");
    assert_eq!(data[0]["output"], "owned.o");
    std::fs::write(root.path().join("chosen.json"), "[]").unwrap();
    snapshot.verify_unchanged().unwrap();
    let path = snapshot.path().to_path_buf();
    drop(snapshot);
    assert!(!path.exists());
}

#[test]
fn rejects_invalid_shapes_commands_and_excessive_input() {
    let root = tempfile::tempdir().unwrap();
    for raw in [
        b"not json".as_slice(),
        b"{}",
        b"[null]",
        b"[{\"directory\":\".\",\"file\":\"a.c\"}]",
        b"[{\"directory\":\".\",\"file\":\"a.c\",\"arguments\":[]}]",
        b"[{\"directory\":\".\",\"file\":\"a.c\",\"arguments\":[7]}]",
    ] {
        assert!(capture(root.path(), raw).is_err());
    }
    assert!(capture(root.path(), &vec![b' '; MAX_COMPILE_DATABASE_BYTES + 1]).is_err());
}

#[test]
fn limits_command_count_and_normalized_size_before_retention() {
    let root = tempfile::tempdir().unwrap();
    let commands = format!("[{}]", vec!["{}"; 100_001].join(","));
    let error = capture(root.path(), commands.as_bytes()).err().unwrap();
    assert!(error.to_string().contains("100000 commands"));
    let mut command =
        json!([{"directory":".","file":"owned.c","arguments":["clang"],"padding":""}]);
    let overhead = serde_json::to_vec(&command).unwrap().len();
    command[0]["padding"] = json!("x".repeat(MAX_COMPILE_DATABASE_BYTES - overhead));
    let raw = serde_json::to_vec(&command).unwrap();
    assert_eq!(raw.len(), MAX_COMPILE_DATABASE_BYTES);
    let error = capture(root.path(), &raw).err().unwrap();
    assert!(error
        .to_string()
        .contains("prepared compiler database exceeds"));
}

#[test]
fn allows_command_strings_and_empty_catalogs_without_executing_them() {
    let root = tempfile::tempdir().unwrap();
    let snapshot = capture(
        root.path(),
        br#"[{"directory":".","file":"owned.c","command":"owned-never-executed -c owned.c"}]"#,
    )
    .unwrap();
    assert_eq!(snapshot.receipt().entries, 1);
    assert_eq!(capture(root.path(), b"[]").unwrap().receipt().entries, 0);
}

#[test]
fn detects_changed_private_snapshot_bytes() {
    let root = tempfile::tempdir().unwrap();
    let snapshot = capture(root.path(), b"[]").unwrap();
    std::fs::write(snapshot.path(), "[ ]").unwrap();
    assert!(snapshot.verify_unchanged().is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_configuration_and_ungranted_paths() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let source = outside.path().join("external.json");
    std::fs::write(&source, "[]").unwrap();
    let link = root.path().join("linked.json");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    assert!(CompileDatabaseSnapshot::capture(&capability, &source).is_err());
    assert!(CompileDatabaseSnapshot::capture(&capability, &link).is_err());
}
