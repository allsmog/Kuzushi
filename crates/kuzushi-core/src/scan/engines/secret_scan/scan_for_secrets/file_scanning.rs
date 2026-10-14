use super::super::scanner_options::MAX_SUPPORTED_FILE_BYTES;
use super::content_budget::ContentBudget;
use super::*;

pub(super) struct SecretFileGap {
    pub(super) error: std::io::Error,
    pub(super) halt: bool,
    pub(super) skipped: bool,
}

pub(super) enum SecretFileScan {
    Scanned,
    Skipped,
    /// The walk selected this file but its content could not be read, so
    /// nothing was searched in it. Neither counter may claim it.
    Unreadable(SecretFileGap),
}

pub(super) fn scan_secret_file(
    root: &Path,
    file_path: &Path,
    options: &SecretScanOptions,
    budget: &mut ContentBudget,
    findings: &mut Vec<SecretScanFinding>,
) -> SecretFileScan {
    let bytes = match read_secret_file_bytes(root, file_path, options, budget) {
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
    Unreadable(SecretFileGap),
}

fn read_secret_file_bytes(
    root: &Path,
    file_path: &Path,
    options: &SecretScanOptions,
    budget: &mut ContentBudget,
) -> SecretFileRead {
    if is_binary_extension(file_path, &options.binary_exts) {
        return SecretFileRead::Skipped;
    }

    let bytes = match read_reserved_file(root, file_path, options, budget) {
        Ok(bytes) => bytes,
        Err(error) => return SecretFileRead::Unreadable(error),
    };
    if is_likely_binary(&bytes) {
        return SecretFileRead::Skipped;
    }
    SecretFileRead::Bytes(bytes)
}

fn read_reserved_file(
    root: &Path,
    path: &Path,
    options: &SecretScanOptions,
    budget: &mut ContentBudget,
) -> Result<Vec<u8>, SecretFileGap> {
    let file = crate::bounded_file::open_regular_file_within(root, path).map_err(read_gap)?;
    let length = file.metadata().map_err(read_gap)?.len();
    if length > options.max_file_bytes.min(MAX_SUPPORTED_FILE_BYTES) {
        return Err(SecretFileGap {
            error: std::io::Error::other(
                "per-file content allowance exceeded; file was not inspected",
            ),
            halt: false,
            skipped: true,
        });
    }
    budget.reserve(length).map_err(|error| SecretFileGap {
        error: std::io::Error::other(error.to_string()),
        halt: true,
        skipped: false,
    })?;
    crate::bounded_file::read_open_regular_bytes(path, file, length as usize).map_err(read_gap)
}

fn read_gap(error: std::io::Error) -> SecretFileGap {
    SecretFileGap {
        error,
        halt: false,
        skipped: false,
    }
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
            &mut ContentBudget::new(536_870_912),
            &mut findings,
        );

        assert!(matches!(outcome, SecretFileScan::Unreadable(_)));
        assert!(findings.is_empty());
    }

    /// A file past the configured size bound is a deliberate limit, not a
    /// failure, so it stays in the skipped count rather than the gap list.
    #[test]
    fn an_oversized_file_remains_skipped_and_discloses_incomplete_coverage() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("big.env");
        std::fs::write(&path, "x".repeat(4096)).unwrap();
        let options = SecretScanOptions {
            max_file_bytes: 1024,
            ..SecretScanOptions::default()
        };
        let mut findings = Vec::new();

        let outcome = scan_secret_file(
            temp.path(),
            &path,
            &options,
            &mut ContentBudget::new(536_870_912),
            &mut findings,
        );

        let SecretFileScan::Unreadable(gap) = outcome else {
            panic!("size omission needs a receipt")
        };
        assert!(gap.skipped);
        assert!(!gap.halt);
    }
}
