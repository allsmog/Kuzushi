use super::*;

fn canonical_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

#[cfg(unix)]
#[test]
fn fifo_file_open_returns_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let owned = canonical_tempdir();
    let path = owned.path().join("source.rs");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let root = owned.path().to_owned();
    let candidate = path.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(
            InventoryRoot::new(&root)
                .unwrap()
                .open_file(&candidate)
                .is_err(),
        )
        .unwrap();
    });
    let result = receive.recv_timeout(std::time::Duration::from_secs(2));
    if result.is_err() {
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path);
    }
    assert_eq!(result.unwrap(), true);
    worker.join().unwrap();
}

#[cfg(unix)]
#[test]
fn pinned_root_does_not_rebind_to_a_replacement_symlink() {
    let owned = canonical_tempdir();
    let external = canonical_tempdir();
    let root = owned.path().join("repository");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("owned.rs"), "// owned source\n").unwrap();
    std::fs::write(external.path().join("external.rs"), "// excluded source\n").unwrap();
    let reader = InventoryRoot::new(&root).unwrap();
    std::fs::rename(&root, owned.path().join("original")).unwrap();
    std::os::unix::fs::symlink(external.path(), &root).unwrap();
    let entries = reader
        .read_directory(&root)
        .unwrap()
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, root.join("owned.rs"));
    let mut text = String::new();
    std::io::Read::read_to_string(
        &mut reader.open_file(&root.join("owned.rs")).unwrap(),
        &mut text,
    )
    .unwrap();
    assert_eq!(text, "// owned source\n");
    assert!(reader.open_file(&root.join("external.rs")).is_err());
    assert!(reader.verify_current_root().is_err());
}

#[cfg(unix)]
#[test]
fn iterator_remains_on_the_opened_directory_after_its_path_changes() {
    let owned = canonical_tempdir();
    let external = canonical_tempdir();
    let boundary = owned.path().join("service");
    std::fs::create_dir(&boundary).unwrap();
    std::fs::write(boundary.join("owned.rs"), "// owned source\n").unwrap();
    std::fs::write(external.path().join("external.rs"), "// excluded source\n").unwrap();
    let reader = InventoryRoot::new(owned.path()).unwrap();
    let iterator = reader.read_directory(&boundary).unwrap();
    std::fs::rename(&boundary, owned.path().join("original-service")).unwrap();
    std::os::unix::fs::symlink(external.path(), &boundary).unwrap();
    let entries = iterator.collect::<io::Result<Vec<_>>>().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, boundary.join("owned.rs"));
    assert!(reader.open_file(&boundary.join("owned.rs")).is_err());
    assert!(reader.read_directory(&boundary).is_err());
}

#[cfg(unix)]
#[test]
fn file_open_rejects_an_escaping_path_and_every_symlink_component() {
    let owned = canonical_tempdir();
    let external = canonical_tempdir();
    std::fs::write(external.path().join("source.rs"), "// excluded source\n").unwrap();
    std::os::unix::fs::symlink(external.path(), owned.path().join("link")).unwrap();
    let reader = InventoryRoot::new(owned.path()).unwrap();
    assert!(reader
        .open_file(&external.path().join("source.rs"))
        .is_err());
    assert!(reader
        .open_file(&owned.path().join("link/source.rs"))
        .is_err());
    assert!(reader.read_directory(&owned.path().join("link")).is_err());
    assert!(reader
        .open_file(&owned.path().join("../source.rs"))
        .is_err());
}

#[test]
fn binary_sniffing_cannot_read_beyond_an_inventory_reservation() {
    use std::io::Read;
    let mut reader = std::io::Cursor::new(vec![b'a'; 8192]);
    let text = crate::bounded_file::read_source_text_prefix_from_reader((&mut reader).take(8), 8)
        .unwrap()
        .unwrap();
    assert_eq!(text, "aaaaaaaa");
    assert_eq!(reader.position(), 8);
}

#[cfg(unix)]
#[test]
fn growing_file_keeps_the_approved_prefix_bound() {
    use std::io::{Read, Write};
    let owned = canonical_tempdir();
    let path = owned.path().join("source.rs");
    std::fs::write(&path, "// owned").unwrap();
    let file = InventoryRoot::new(owned.path())
        .unwrap()
        .open_file(&path)
        .unwrap();
    let approved = file.metadata().unwrap().len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&vec![b'x'; 8192])
        .unwrap();
    let text = crate::bounded_file::read_source_text_prefix_from_reader(
        file.take(approved),
        approved as usize,
    )
    .unwrap()
    .unwrap();
    assert_eq!(text, "// owned");
}

#[cfg(unix)]
#[test]
fn leaf_classification_excludes_known_links_without_following_unsafe_ancestors() {
    let owned = canonical_tempdir();
    let external = canonical_tempdir();
    std::fs::write(owned.path().join("owned.rs"), "// owned source\n").unwrap();
    std::fs::write(external.path().join("source.rs"), "// excluded source\n").unwrap();
    std::os::unix::fs::symlink(external.path(), owned.path().join("boundary")).unwrap();
    std::os::unix::fs::symlink("missing.rs", owned.path().join("broken.rs")).unwrap();
    let reader = InventoryRoot::new(owned.path()).unwrap();
    assert!(reader.is_known_non_regular(&owned.path().join("boundary")));
    assert!(reader.is_known_non_regular(&owned.path().join("broken.rs")));
    for path in [
        owned.path().join("owned.rs"),
        owned.path().join("missing.rs"),
        owned.path().join("boundary/source.rs"),
        owned.path().join("../source.rs"),
        external.path().join("source.rs"),
    ] {
        assert!(!reader.is_known_non_regular(&path));
    }
    assert!(reader.open_file(&owned.path().join("broken.rs")).is_err());
    assert!(reader
        .open_file(&owned.path().join("boundary/source.rs"))
        .is_err());
}
