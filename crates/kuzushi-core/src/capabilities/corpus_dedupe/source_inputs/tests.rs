use super::*;

#[test]
fn literal_source_paths_are_cached_once_and_keep_their_digest() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join(" source.txt "), "owned source\n").unwrap();
    std::fs::write(root.join("source.txt"), "different").unwrap();
    let mut input = SourceInputs::new(&root, 32);
    assert_eq!(input.text(" source.txt ").unwrap(), "owned source\n");
    std::fs::write(root.join(" source.txt "), "changed").unwrap();
    assert_eq!(input.text(" source.txt ").unwrap(), "owned source\n");
    let receipt = input.receipt();
    assert_eq!(receipt["reservedBytes"], 13);
    assert_eq!(receipt["files"].as_array().unwrap().len(), 1);
    assert_eq!(
        receipt["files"][0]["sha256"],
        crate::worker_protocol::sha256_digest(b"owned source\n").0
    );
    assert!(!receipt.to_string().contains("owned source"));
}

#[test]
fn oversized_files_are_unavailable_and_retain_unknown_reservations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("large"), vec![b'a'; 100]).unwrap();
    std::fs::write(root.join("small"), "x").unwrap();
    let mut input = SourceInputs::new(&root, 4);
    assert!(input.text("large").is_err());
    assert!(input.text("small").is_err());
    let receipt = input.receipt();
    assert_eq!(receipt["reservedBytes"], 4);
    assert!(receipt["files"][0]["readBytes"].is_null());
    assert_eq!(receipt["files"][1]["readBytes"], 0);
}

#[test]
fn invalid_paths_do_not_consume_source_allowance() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let mut input = SourceInputs::new(&root, 4);
    assert!(input.text("").is_err());
    assert!(input.text("../outside").is_err());
    assert!(input.text(root.to_str().unwrap()).is_err());
    assert_eq!(input.receipt()["reservedBytes"], 0);
}

#[test]
fn aggregate_source_limit_and_utf8_validation_are_explicit() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::write(root.join("one"), "abc").unwrap();
    std::fs::write(root.join("two"), [0xff, 0]).unwrap();
    std::fs::write(root.join("three"), "x").unwrap();
    let mut input = SourceInputs::new(&root, 5);
    assert_eq!(input.text("one").unwrap(), "abc");
    assert!(input.text("two").is_err());
    assert!(input.text("three").is_err());
    assert_eq!(input.receipt()["reservedBytes"], 5);
}

#[cfg(unix)]
#[test]
fn symlinked_source_never_reads_the_owned_outside_file() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let file = outside.path().join("owned-only");
    std::fs::write(&file, "outside fixture text").unwrap();
    std::os::unix::fs::symlink(&file, root.join("linked")).unwrap();
    let mut input = SourceInputs::new(&root, 64);
    assert!(input.text("linked").is_err());
    assert!(!input.receipt().to_string().contains("outside fixture text"));
    assert!(input.receipt()["files"][0]["readBytes"].is_null());
    assert_eq!(
        std::fs::read_to_string(file).unwrap(),
        "outside fixture text"
    );
}
