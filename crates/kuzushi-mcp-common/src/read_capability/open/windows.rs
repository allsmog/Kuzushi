use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::File;
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, VOLUME_NAME_DOS,
};

const MAX_FINAL_PATH_UTF16: usize = 32_768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowsFileIdentity {
    pub(super) volume_serial_number: u64,
    pub(super) file_id: [u8; 16],
}

pub(super) fn open_root_directory(path: &Path) -> Result<File> {
    let root = open_path(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .with_context(|| format!("could not open MCP read root: {}", path.display()))?;
    verify_root_handle(&root, path)?;
    Ok(root)
}

pub(super) fn open_file_beneath(
    root: &File,
    retained_root_identity: WindowsFileIdentity,
    path: &Path,
) -> Result<File> {
    reject_reparse_components(path)?;
    let file = open_path(
        path,
        GENERIC_READ,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .with_context(|| format!("could not open authorized MCP path: {}", path.display()))?;
    reject_reparse_handle(&file, path)?;
    verify_retained_root(root, retained_root_identity)?;
    verify_same_volume(root, &file)?;
    verify_final_path_containment(root, &file, path)?;
    Ok(file)
}

pub(super) fn open_visible_directory(path: &Path) -> Result<File> {
    reject_reparse_components(path)?;
    let directory = open_path(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    reject_reparse_handle(&directory, path)?;
    Ok(directory)
}

pub(super) fn file_identity(file: &File) -> Result<WindowsFileIdentity> {
    let info: FILE_ID_INFO = query_handle_info(file, FileIdInfo)?;
    Ok(WindowsFileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

pub(super) fn file_change_time(file: &File) -> Result<i64> {
    let info: FILE_BASIC_INFO = query_handle_info(file, FileBasicInfo)?;
    Ok(info.ChangeTime)
}

pub(super) fn ensure_open_by_file_id_supported(directory: &File) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
    use windows_sys::Win32::System::SystemServices::FILE_SUPPORTS_OPEN_BY_FILE_ID;

    let mut flags = 0_u32;
    // SAFETY: the retained directory handle is live, the flags pointer is
    // writable, and all omitted output buffers are represented by nulls.
    let succeeded = unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut flags,
            std::ptr::null_mut(),
            0,
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not inspect retained MCP directory volume capabilities");
    }
    anyhow::ensure!(
        flags & FILE_SUPPORTS_OPEN_BY_FILE_ID != 0,
        "retained MCP tree traversal requires FILE_SUPPORTS_OPEN_BY_FILE_ID; \
         SMB and FAT/exFAT volumes are unsupported"
    );
    Ok(())
}

fn open_path(path: &Path, access: u32, flags: u32) -> Result<File> {
    let path = nul_terminated_path(path)?;
    // SAFETY: `path` is NUL-terminated, the security/template pointers are
    // null, and a successful owned handle is transferred directly to `File`.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("CreateFileW failed");
    }
    // SAFETY: `CreateFileW` returned a fresh, valid, owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn nul_terminated_path(path: &Path) -> Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    anyhow::ensure!(!encoded.contains(&0), "MCP path contains a NUL code unit");
    encoded.push(0);
    Ok(encoded)
}

fn verify_retained_root(root: &File, expected: WindowsFileIdentity) -> Result<()> {
    anyhow::ensure!(
        file_identity(root)? == expected,
        "retained MCP read root identity changed"
    );
    Ok(())
}

fn verify_root_handle(root: &File, expected_path: &Path) -> Result<()> {
    let attributes: FILE_ATTRIBUTE_TAG_INFO = query_handle_info(root, FileAttributeTagInfo)?;
    anyhow::ensure!(
        attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to retain an MCP read-root reparse point"
    );
    anyhow::ensure!(
        final_path(root)? == expected_path,
        "MCP read root changed while its capability was created"
    );
    Ok(())
}

fn reject_reparse_handle(file: &File, path: &Path) -> Result<()> {
    let attributes: FILE_ATTRIBUTE_TAG_INFO = query_handle_info(file, FileAttributeTagInfo)?;
    anyhow::ensure!(
        attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to follow an MCP reparse point: {}",
        path.display()
    );
    Ok(())
}

fn reject_reparse_components(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&prefix)
            .with_context(|| format!("could not inspect MCP path: {}", prefix.display()))?;
        anyhow::ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "refusing to follow an MCP reparse point: {}",
            prefix.display()
        );
    }
    Ok(())
}

fn verify_same_volume(root: &File, file: &File) -> Result<()> {
    let root_identity = file_identity(root)?;
    let file_identity = file_identity(file)?;
    anyhow::ensure!(
        root_identity.volume_serial_number == file_identity.volume_serial_number,
        "opened MCP file is not on the retained read-root volume"
    );
    Ok(())
}

fn verify_final_path_containment(root: &File, file: &File, requested: &Path) -> Result<()> {
    let root_path = final_path(root)?;
    let file_path = final_path(file)?;
    anyhow::ensure!(
        path_is_beneath_or_equal(&file_path, &root_path),
        "opened MCP file escaped the retained read root: {}",
        requested.display()
    );
    Ok(())
}

fn path_is_beneath_or_equal(candidate: &Path, root: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

fn final_path(file: &File) -> Result<PathBuf> {
    let handle = file.as_raw_handle();
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: a null buffer with zero length is the documented sizing call.
    let required = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(std::io::Error::last_os_error()).context("could not size final handle path");
    }
    let capacity = required as usize + 1;
    anyhow::ensure!(
        capacity <= MAX_FINAL_PATH_UTF16,
        "final MCP handle path exceeds the supported Windows path size"
    );
    let mut buffer = vec![0_u16; capacity];
    // SAFETY: `buffer` is writable for its advertised length and `handle` is live.
    let written = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, flags)
    };
    if written == 0 {
        return Err(std::io::Error::last_os_error()).context("could not resolve final handle path");
    }
    anyhow::ensure!(
        (written as usize) < buffer.len(),
        "final MCP handle path changed while it was queried"
    );
    buffer.truncate(written as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn query_handle_info<T>(file: &File, class: i32) -> Result<T> {
    let mut info = MaybeUninit::<T>::zeroed();
    let size = u32::try_from(size_of::<T>()).context("Windows file identity is too large")?;
    // SAFETY: `info` points to `size_of::<T>()` writable bytes and the selected
    // information classes exactly match the concrete `T` used by callers.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            class,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not query Windows file identity");
    }
    // SAFETY: the successful API call initialized the entire fixed-size struct.
    Ok(unsafe { info.assume_init() })
}
