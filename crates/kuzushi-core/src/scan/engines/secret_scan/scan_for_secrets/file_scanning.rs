use super::super::scanner_options::MAX_SUPPORTED_FILE_BYTES;
use super::*;

pub(super) enum SecretFileScan {
    Scanned,
    Skipped,
    Ignored,
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
        SecretFileRead::Ignored => return SecretFileScan::Ignored,
    };

    let text = String::from_utf8_lossy(&bytes);
    let rel_path = secret_relative_path(root, file_path);
    finding_builder::append_secret_hits(root, &rel_path, &text, options.max_findings, findings);
    SecretFileScan::Scanned
}

enum SecretFileRead {
    Bytes(Vec<u8>),
    Skipped,
    Ignored,
}

fn read_secret_file_bytes(file_path: &Path, options: &SecretScanOptions) -> SecretFileRead {
    if is_binary_extension(file_path, &options.binary_exts) {
        return SecretFileRead::Skipped;
    }

    let max_bytes =
        usize::try_from(options.max_file_bytes).unwrap_or(MAX_SUPPORTED_FILE_BYTES as usize);
    let bytes = match crate::bounded_file::read_regular_bytes(file_path, max_bytes) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return SecretFileRead::Skipped;
        }
        Err(_) => return SecretFileRead::Ignored,
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
