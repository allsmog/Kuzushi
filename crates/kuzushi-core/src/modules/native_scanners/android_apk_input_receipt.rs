//! Bounded archive identity. A matching digest does not authenticate decompilation.
use crate::scan::ScanCancellation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

pub(super) const DEFAULT_APK_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_APK_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ApkInputReceipt {
    schema_version: u32,
    path: String,
    bytes: u64,
    sha256: String,
    decompiled_source_verified: bool,
}

impl ApkInputReceipt {
    pub(super) fn from_value(value: &Value) -> Result<Self> {
        serde_json::from_value(value.clone()).context("APK input receipt is missing or malformed")
    }
    pub(super) fn capture(input: &Value, cancel: &ScanCancellation) -> Result<Self> {
        let path = super::android_apk_prepare::resolve_apk_path(input)?;
        let max_bytes = apk_byte_limit(input)?;
        let mut file = open_regular_archive(&path, max_bytes)?;
        let (bytes, sha256) = archive_digest(&mut file, max_bytes, cancel)?;
        Ok(Self {
            schema_version: 1,
            path: path.display().to_string(),
            bytes,
            sha256,
            decompiled_source_verified: false,
        })
    }

    pub(super) fn require_unchanged(&self, input: &Value, cancel: &ScanCancellation) -> Result<()> {
        let current = Self::capture(input, cancel)?;
        anyhow::ensure!(current.bytes == self.bytes && current.sha256 == self.sha256,
            "APK input changed during analysis; inspect recorded diagnostics before another attempt");
        Ok(())
    }
}

fn apk_byte_limit(input: &Value) -> Result<u64> {
    let bytes = input
        .get("maxApkBytes")
        .or_else(|| input.get("max_apk_bytes"))
        .map(|value| {
            value
                .as_u64()
                .context("maxApkBytes must be a positive integer")
        })
        .transpose()?
        .unwrap_or(DEFAULT_APK_BYTES);
    anyhow::ensure!(
        (1..=MAX_APK_BYTES).contains(&bytes),
        "maxApkBytes must be from 1 to {MAX_APK_BYTES}"
    );
    Ok(bytes)
}

fn open_regular_archive(path: &Path, limit: u64) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("Could not inspect APK {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "APK input must be a regular file");
    anyhow::ensure!(
        metadata.len() <= limit,
        "APK input exceeds the {limit}-byte inspection limit"
    );
    Ok(file)
}

fn archive_digest(file: &mut File, limit: u64, cancel: &ScanCancellation) -> Result<(u64, String)> {
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        anyhow::ensure!(!cancel.is_cancelled(), "APK input inspection canceled");
        let count = file.read(&mut buffer).context("Could not read APK input")?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        anyhow::ensure!(
            bytes <= limit,
            "APK input grew beyond the {limit}-byte inspection limit"
        );
        digest.update(&buffer[..count]);
    }
    let hex: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((bytes, format!("sha256:{hex}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receipt_tracks_archive_bytes_and_refuses_source_drift() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned.apk");
        std::fs::write(&path, b"owned inert archive").unwrap();
        let value = json!({"apk":path});
        let cancel = ScanCancellation::default();
        let receipt = ApkInputReceipt::capture(&value, &cancel).unwrap();
        assert_eq!(
            receipt.sha256,
            crate::run_lifecycle::sha256_content_digest(b"owned inert archive")
        );
        receipt.require_unchanged(&value, &cancel).unwrap();
        std::fs::write(&path, b"changed inert archive").unwrap();
        assert!(receipt.require_unchanged(&value, &cancel).is_err());
    }

    #[test]
    fn invalid_limits_oversized_input_and_cancellation_are_honest() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned.apk");
        std::fs::write(&path, b"owned archive").unwrap();
        for limit in [0, 1, MAX_APK_BYTES + 1] {
            assert!(ApkInputReceipt::capture(
                &json!({"apk":path,"maxApkBytes":limit}),
                &ScanCancellation::default()
            )
            .is_err());
        }
        let cancel = ScanCancellation::default();
        cancel.cancel();
        assert!(ApkInputReceipt::capture(&json!({"apk":path}), &cancel).is_err());
    }
}
