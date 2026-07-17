use super::super::super::sha256_digest;
use std::path::Path;

pub(super) fn target_binding(target: &Path) -> String {
    sha256_digest(&target_identity_bytes(target)).0
}

#[cfg(unix)]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    target.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    encode_wide_identity(target.as_os_str().encode_wide())
}

#[cfg(not(any(unix, windows)))]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    target.as_os_str().as_encoded_bytes().to_vec()
}

#[cfg(any(windows, test))]
fn encode_wide_identity(wide: impl IntoIterator<Item = u16>) -> Vec<u8> {
    wide.into_iter().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::encode_wide_identity;

    #[test]
    fn windows_wide_identity_is_lossless() {
        assert_ne!(
            encode_wide_identity([0xd800]),
            encode_wide_identity([0xd801])
        );
    }
}
