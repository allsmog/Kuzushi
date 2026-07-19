use super::entry_file_type;
use crate::read_capability::directory_entries::{ensure_capacity, EntryIdentity, EntryRecord};
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::File;
use std::mem::{size_of, size_of_val};

pub(super) fn entries(directory: &File, max_entries: usize) -> Result<Vec<EntryRecord>> {
    let reopened = reopen_directory(directory)?;
    let mut enumeration = WindowsDirectoryEnumeration::new(reopened);
    let mut entries = Vec::new();
    while let Some(batch) = enumeration.next_batch()? {
        append_batch(&mut entries, &batch, max_entries)?;
    }
    Ok(entries)
}

fn reopen_directory(directory: &File) -> Result<File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        ReOpenFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    // SAFETY: the source handle is live. A successful fresh handle is
    // transferred immediately into `File` ownership.
    let handle = unsafe {
        ReOpenFile(
            directory.as_raw_handle(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .context("could not reopen retained MCP directory handle");
    }
    // SAFETY: `ReOpenFile` returned a fresh, valid, owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

struct WindowsDirectoryEnumeration {
    directory: File,
    restart: bool,
}

impl WindowsDirectoryEnumeration {
    fn new(directory: File) -> Self {
        Self {
            directory,
            restart: true,
        }
    }

    fn next_batch(&mut self) -> Result<Option<Vec<u64>>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_NO_MORE_FILES};
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, GetFileInformationByHandleEx,
        };

        const BUFFER_BYTES: usize = 64 * 1024;
        let mut buffer = vec![0_u64; BUFFER_BYTES / size_of::<u64>()];
        let class = if self.restart {
            FileIdExtdDirectoryRestartInfo
        } else {
            FileIdExtdDirectoryInfo
        };
        self.restart = false;
        // SAFETY: `buffer` is aligned and writable for the advertised size;
        // the reopened directory handle remains live for the call.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                self.directory.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
            )
        };
        if succeeded != 0 {
            return Ok(Some(buffer));
        }
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error().map(|code| code as u32),
            Some(ERROR_NO_MORE_FILES) | Some(ERROR_HANDLE_EOF)
        ) {
            return Ok(None);
        }
        Err(error).context("could not enumerate retained MCP directory handle")
    }
}

fn append_batch(entries: &mut Vec<EntryRecord>, buffer: &[u64], max_entries: usize) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO;

    let mut offset = 0_usize;
    loop {
        let record = record_at(buffer, offset)?;
        let name = record_name(buffer, offset, &record)?;
        if name != "." && name != ".." {
            ensure_capacity(entries.len(), max_entries)?;
            anyhow::ensure!(
                record.FileId.Identifier != [0; 16],
                "MCP directory entry has no stable file identity"
            );
            entries.push(EntryRecord {
                name,
                identity: EntryIdentity::Windows {
                    file_id: record.FileId.Identifier,
                    file_type: entry_file_type(record.FileAttributes),
                },
            });
        }
        if record.NextEntryOffset == 0 {
            return Ok(());
        }
        let advance = record.NextEntryOffset as usize;
        anyhow::ensure!(
            advance >= size_of::<FILE_ID_EXTD_DIR_INFO>(),
            "malformed Windows directory enumeration record"
        );
        offset = offset
            .checked_add(advance)
            .context("Windows directory enumeration offset overflow")?;
    }
}

fn record_at(
    buffer: &[u64],
    offset: usize,
) -> Result<windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO;

    let bytes = size_of_val(buffer);
    anyhow::ensure!(
        offset <= bytes.saturating_sub(size_of::<FILE_ID_EXTD_DIR_INFO>()),
        "malformed Windows directory enumeration record"
    );
    // SAFETY: the complete fixed header was bounds-checked above. Unaligned
    // reads also tolerate a malformed kernel record offset without UB.
    Ok(unsafe {
        std::ptr::read_unaligned(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<FILE_ID_EXTD_DIR_INFO>(),
        )
    })
}

fn record_name(
    buffer: &[u64],
    record_offset: usize,
    record: &windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO,
) -> Result<OsString> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ID_EXTD_DIR_INFO;

    let name_bytes = record.FileNameLength as usize;
    let name_offset = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
    anyhow::ensure!(
        name_bytes.is_multiple_of(2),
        "malformed Windows directory entry name"
    );
    let start = record_offset
        .checked_add(name_offset)
        .context("Windows directory entry name offset overflow")?;
    let end = start
        .checked_add(name_bytes)
        .context("Windows directory entry name length overflow")?;
    let record_end = match record.NextEntryOffset {
        0 => size_of_val(buffer),
        advance => record_offset
            .checked_add(advance as usize)
            .context("Windows directory entry boundary overflow")?,
    };
    anyhow::ensure!(
        end <= record_end && record_end <= size_of_val(buffer),
        "malformed Windows directory entry name"
    );
    // SAFETY: the byte view has exactly the initialized allocation's extent
    // and does not outlive the borrowed u64 buffer.
    let buffer_bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(buffer)) };
    let encoded = buffer_bytes
        .get(start..end)
        .context("malformed Windows directory entry name")?;
    let units = encoded
        .chunks_exact(size_of::<u16>())
        .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    Ok(OsString::from_wide(&units))
}
