use anyhow::Result;
use kuzushi_mcp_common::{bounded_bundle_identity, copy_bounded_bundle, BundleIdentityConfig};
use std::path::Path;

pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_ENTRIES: u64 =
    500_000;
pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_BYTES: u64 =
    16 * 1024 * 1024 * 1024;
pub(in crate::codeql_repository_execution::launcher) const MAX_EXTERNAL_BUNDLE_DEPTH: usize = 128;

const EXTERNAL_BUNDLE_CONFIG: BundleIdentityConfig = BundleIdentityConfig::new(
    b"kuzushi-codeql-external-bundle-v1\0",
    "CodeQL external bundle",
    MAX_EXTERNAL_BUNDLE_ENTRIES,
    MAX_EXTERNAL_BUNDLE_BYTES,
    MAX_EXTERNAL_BUNDLE_DEPTH,
);

pub(in crate::codeql_repository_execution::launcher) fn external_bundle_identity(
    root: &Path,
) -> Result<String> {
    bounded_bundle_identity(root, EXTERNAL_BUNDLE_CONFIG)
}

pub(in crate::codeql_repository_execution::launcher) fn snapshot_external_bundle(
    root: &Path,
    destination: &Path,
    expected: &str,
) -> Result<()> {
    let actual = copy_bounded_bundle(root, destination, EXTERNAL_BUNDLE_CONFIG)?;
    anyhow::ensure!(
        actual == expected,
        "CodeQL external bundle changed after preparation; prepare and authorize the operation again"
    );
    Ok(())
}
