use super::*;
use crate::ScanCancellation;
use std::fs;

#[test]
pub(crate) fn cancellation_stops_native_scan() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("keys.txt"),
        "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
    )
    .unwrap();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();

    let err = SecretScanScanner
        .scan(temp.path(), &cancellation)
        .unwrap_err()
        .to_string();

    assert!(err.contains("cancelled"));
}
