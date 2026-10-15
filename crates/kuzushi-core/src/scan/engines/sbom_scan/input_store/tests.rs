use super::*;

fn inputs(root: &Path, total: usize) -> SbomInputs {
    SbomInputs::new(
        root,
        SbomScanOptions {
            max_total_bytes: total,
            ..Default::default()
        },
        ScanCancellation::default(),
    )
    .unwrap()
}

#[test]
fn repeated_and_dot_path_reads_reuse_one_immutable_capture() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("package.json");
    std::fs::write(&path, "original").unwrap();
    let source = inputs(root.path(), 8);
    let first = source.bytes(&path).unwrap();
    std::fs::write(&path, "changed source").unwrap();
    let second = source.bytes(&root.path().join("./package.json")).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(first.as_slice(), b"original");
    let receipt = source.inspection();
    assert_eq!(receipt.source_bytes_read, 8);
    assert_eq!(receipt.reserved_source_bytes, 8);
    assert_eq!(receipt.captured_files, 1);
    assert_eq!(receipt.inputs[0].sha256, digest(b"original"));
}

#[test]
fn aggregate_admission_stops_before_reading_another_file() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a"), b"first").unwrap();
    std::fs::write(root.path().join("b"), b"second").unwrap();
    let source = inputs(root.path(), 10);
    source.bytes(&root.path().join("a")).unwrap();
    let error = source.bytes(&root.path().join("b")).unwrap_err();
    assert!(error.to_string().contains("maxTotalBytes 10"));
    let receipt = source.inspection();
    assert_eq!(receipt.source_bytes_read, 5);
    assert_eq!(receipt.reserved_source_bytes, 5);
    assert_eq!(receipt.captured_files, 1);
}

#[test]
fn a_file_limit_refuses_content_without_a_reservation() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("large");
    std::fs::write(&path, b"large").unwrap();
    let source = SbomInputs::new(
        root.path(),
        SbomScanOptions {
            max_file_bytes: 4,
            max_total_bytes: 10,
        },
        Default::default(),
    )
    .unwrap();
    assert!(source
        .bytes(&path)
        .unwrap_err()
        .to_string()
        .contains("maxFileBytes 4"));
    assert_eq!(source.inspection().source_bytes_read, 0);
    assert_eq!(source.inspection().reserved_source_bytes, 0);
}

#[test]
fn cancellation_also_refuses_cached_results() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source");
    std::fs::write(&path, b"text").unwrap();
    let source = inputs(root.path(), 4);
    source.bytes(&path).unwrap();
    source.cancellation.cancel();
    assert_eq!(
        source.bytes(&path).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(source.inspection().source_bytes_read, 4);
}

struct CancelAfterRead {
    bytes: std::io::Cursor<Vec<u8>>,
    cancellation: ScanCancellation,
}

impl Read for CancelAfterRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.read(output)?;
        self.cancellation.cancel();
        Ok(count)
    }
}

#[test]
fn cancellation_interrupts_capture_between_bounded_chunks() {
    let cancellation = ScanCancellation::default();
    let mut reader = CancelAfterRead {
        bytes: std::io::Cursor::new(vec![b'x'; 128 * 1024]),
        cancellation: cancellation.clone(),
    };
    let read = Cell::new(0);
    assert_eq!(
        read_capture(&mut reader, 128 * 1024, &cancellation, &read)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(read.get(), 64 * 1024);
}

#[test]
fn early_eof_retains_known_consumption_without_publishing_a_capture() {
    let read = Cell::new(0);
    let mut reader = std::io::Cursor::new(b"short");
    assert_eq!(
        read_capture(&mut reader, 10, &Default::default(), &read)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(read.get(), 5);
}

#[cfg(unix)]
#[test]
fn symlinked_inputs_and_replaced_roots_are_never_read() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("repository");
    std::fs::create_dir(&root).unwrap();
    let outside = parent.path().join("outside");
    std::fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let source = inputs(&root, 100);
    assert!(source.bytes(&root.join("link")).is_err());
    std::fs::rename(&root, parent.path().join("prior")).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("new"), b"different root").unwrap();
    assert!(source.bytes(&root.join("new")).is_err());
    assert_eq!(source.inspection().source_bytes_read, 0);
}
