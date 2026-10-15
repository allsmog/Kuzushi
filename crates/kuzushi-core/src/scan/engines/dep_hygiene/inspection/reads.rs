use super::*;

pub(super) const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn read_manifest(
    root: &Path,
    path: &Path,
    receipt: &mut HygieneInspectionReceipt,
) -> Result<String> {
    let file = crate::bounded_file::open_regular_file_within(root, path)?;
    let length = file.metadata()?.len();
    anyhow::ensure!(
        length <= MAX_MANIFEST_BYTES as u64,
        "manifest exceeds maximum supported size ({MAX_MANIFEST_BYTES}-byte file limit); full document was not read"
    );
    let reservation = length
        .checked_add(1)
        .context("manifest read size overflow")?;
    reserve_read(receipt, reservation)?;
    let bytes = crate::bounded_file::read_open_regular_bytes(path, file, length as usize)?;
    String::from_utf8(bytes).context("manifest is not UTF-8")
}

fn reserve_read(receipt: &mut HygieneInspectionReceipt, bytes: u64) -> Result<()> {
    let total = receipt
        .content_bytes_reserved
        .checked_add(bytes)
        .context("manifest read allowance overflow")?;
    anyhow::ensure!(
        total <= MAX_READ_BYTES,
        "shared {MAX_READ_BYTES}-byte read allowance exhausted; manifest was not read"
    );
    receipt.content_bytes_reserved = total;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_read_allowance_is_reserved_before_content_io() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("package.json");
        fs::write(&path, "{}").unwrap();
        let mut inspection = HygieneInspection::new(root.path(), 1, 1);
        inspection.receipt.content_bytes_reserved = MAX_READ_BYTES - 2;
        let error = read_manifest(root.path(), &path, &mut inspection.receipt).unwrap_err();
        assert!(error.to_string().contains("allowance exhausted"));
        assert_eq!(
            inspection.receipt.content_bytes_reserved,
            MAX_READ_BYTES - 2
        );
    }

    #[test]
    fn decoding_failure_keeps_its_read_reservation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("package.json");
        fs::write(&path, [0xff]).unwrap();
        let mut inspection = HygieneInspection::new(root.path(), 1, 1);
        assert!(read_manifest(root.path(), &path, &mut inspection.receipt).is_err());
        assert_eq!(inspection.receipt.content_bytes_reserved, 2);
    }

    #[test]
    fn oversized_manifest_is_not_parsed_or_read_as_a_prefix() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("package.json");
        fs::File::create(&path)
            .unwrap()
            .set_len((MAX_MANIFEST_BYTES + 1) as u64)
            .unwrap();
        let mut inspection = HygieneInspection::new(root.path(), 1, 1);
        assert!(read_manifest(root.path(), &path, &mut inspection.receipt)
            .unwrap_err()
            .to_string()
            .contains("file limit"));
        assert_eq!(inspection.receipt.content_bytes_reserved, 0);
    }
}
