use anyhow::Result;
use std::fs::Metadata;
use std::path::Path;

#[cfg(unix)]
pub(super) fn require_single_link(_path: &Path, metadata: &Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(metadata.nlink() == 1, "cache file must have exactly one hard link");
    Ok(())
}

#[cfg(windows)]
pub(super) fn require_single_link(path: &Path, _metadata: &Metadata) -> Result<()> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES,
    };
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    anyhow::ensure!(information.nNumberOfLinks == 1, "cache file must have exactly one hard link");
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(super) fn require_single_link(_path: &Path, _metadata: &Metadata) -> Result<()> {
    anyhow::bail!("cache file link authentication is unavailable on this platform")
}
