use super::super::scanner_options::MAX_SUPPORTED_FILE_BYTES;
use super::*;

pub(super) enum SecretFileScan {
    Scanned,
    Skipped,
    /// The walk selected this file but its content could not be read, so
    /// nothing was searched in it. Neither counter may claim it.
    Unreadable(std::io::Error),
}

pub(super) fn scan_secret_file(
    root: &Path,
    file_path: &Path,
    options: &SecretScanOptions,
    findings: &mut Vec<SecretScanFinding>,
) -> SecretFileScan {
    let bytes = match read_secret_file_bytes(file_path, options) {
        SecretFileRead::Bytes(bytes) => bytes,
        SecretFileRead::Skipped => return SecretFileScan::Skipped,
        SecretFileRead::Unreadable(error) => return SecretFileScan::Unreadable(error),
    };

    let text = String::from_utf8_lossy(&bytes);
    let rel_path = secret_relative_path(root, file_path);
    finding_builder::append_secret_hits(root, &rel_path, &text, options.max_findings, findings);
    SecretFileScan::Scanned
}

enum SecretFileRead {
    Bytes(Vec<u8>),
    Skipped,
    Unreadable(std::io::Error),
}

fn read_secret_file_bytes(file_path: &Path, options: &SecretScanOptions) -> SecretFileRead {
    if is_binary_extension(file_path, &options.binary_exts) {
        return SecretFileRead::Skipped;
    }

    let max_bytes =
        usize::try_from(options.max_file_bytes).unwrap_or(MAX_SUPPORTED_FILE_BYTES as usize);
    let bytes = match crate::bounded_file::read_regular_bytes(file_path, max_bytes) {
        Ok(bytes) => bytes,
        // Oversized for the configured bound: a deliberate limit the report
        // already counts as skipped.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return SecretFileRead::Skipped;
        }
        // Everything else is a failure to read a file the walk already
        // confirmed was a regular file. Symlinks and other non-regular
        // entries never reach here: `DirEntry::file_type` does not follow
        // links, so `collect_files` only pushes regular files.
        Err(error) => return SecretFileRead::Unreadable(error),
    };
    if is_likely_binary(&bytes) {
        return SecretFileRead::Skipped;
    }
    SecretFileRead::Bytes(bytes)
}

fn secret_relative_path(root: &Path, file_path: &Path) -> String {
    file_path
        .strip_prefix(root)
        .unwrap_or(file_path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An I/O failure on a selected file used to return `Ignored`, which
    /// incremented neither counter: the file left the report entirely.
    #[test]
    fn a_file_that_cannot_be_read_is_reported_as_unreadable() {
        let temp = tempfile::tempdir().unwrap();
        let mut findings = Vec::new();

        let outcome = scan_secret_file(
            temp.path(),
            &temp.path().join("vanished.env"),
            &SecretScanOptions::default(),
            &mut findings,
        );

        assert!(matches!(outcome, SecretFileScan::Unreadable(_)));
        assert!(findings.is_empty());
    }

    /// A file past the configured size bound is a deliberate limit, not a
    /// failure, so it stays in the skipped count rather than the gap list.
    #[test]
    fn an_oversized_file_stays_skipped() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("big.env");
        std::fs::write(&path, "x".repeat(4096)).unwrap();
        let options = SecretScanOptions {
            max_file_bytes: 1024,
            ..SecretScanOptions::default()
        };
        let mut findings = Vec::new();

        let outcome = scan_secret_file(temp.path(), &path, &options, &mut findings);

        assert!(matches!(outcome, SecretFileScan::Skipped));
    }
}
