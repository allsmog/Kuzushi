use super::{EntryIdentity, EntryRecord};
use anyhow::{Context, Result};
use std::fs::File;
use std::mem::{size_of, MaybeUninit};

mod enumeration;

pub(super) fn entries(directory: &File, max_entries: usize) -> Result<Vec<EntryRecord>> {
    enumeration::entries(directory, max_entries)
}

pub(super) fn open_child(directory: &File, record: &EntryRecord) -> Result<File> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let EntryIdentity::Windows { file_id, file_type } = &record.identity;
    anyhow::ensure!(
        file_type & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to open an MCP directory-entry reparse point"
    );
    let file = open_by_id(directory, *file_id)?;
    reject_reparse_point(&file)?;
    Ok(file)
}

fn open_by_id(volume: &File, id: [u8; 16]) -> Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        ExtendedFileIdType, OpenFileById, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: ExtendedFileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            ExtendedFileId: FILE_ID_128 { Identifier: id },
        },
    };
    // SAFETY: the retained parent identifies the volume, the descriptor is
    // fully initialized, and a successful handle is transferred into `File`.
    let handle = unsafe {
        OpenFileById(
            volume.as_raw_handle(),
            &descriptor,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .context("could not open retained Windows directory entry by file ID");
    }
    // SAFETY: `OpenFileById` returned a fresh, valid, owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub(super) fn opened_entry_matches(identity: &EntryIdentity, file: &File) -> Result<bool> {
    let EntryIdentity::Windows {
        file_id: expected_file_id,
        file_type,
    } = identity;
    let opened_file_id = file_id(file)?;
    let opened_file_type = entry_file_type(file_attributes(file)?);
    Ok(opened_file_id == *expected_file_id && opened_file_type == *file_type)
}

pub(super) fn entry_file_type(attributes: u32) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
}

fn reject_reparse_point(file: &File) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    anyhow::ensure!(
        file_attributes(file)? & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "refusing to follow an MCP directory-entry reparse point"
    );
    Ok(())
}

fn file_attributes(file: &File) -> Result<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO,
    };

    let mut info = MaybeUninit::<FILE_ATTRIBUTE_TAG_INFO>::zeroed();
    // SAFETY: `info` is writable for the exact fixed-size information class.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            info.as_mut_ptr().cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not inspect Windows directory entry attributes");
    }
    // SAFETY: the successful API call initialized the fixed-size structure.
    Ok(unsafe { info.assume_init() }.FileAttributes)
}

fn file_id(file: &File) -> Result<[u8; 16]> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    let mut info = MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: `info` is writable for the exact fixed-size information class,
    // and the opened entry handle remains live for the call.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr().cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not verify Windows directory entry identity");
    }
    // SAFETY: the successful API call initialized the fixed-size structure.
    Ok(unsafe { info.assume_init() }.FileId.Identifier)
}
