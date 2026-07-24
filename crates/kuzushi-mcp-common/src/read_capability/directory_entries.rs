use anyhow::Result;
use std::ffi::OsString;
use std::fs::File;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Debug, Clone)]
pub(super) struct EntryRecord {
    pub(super) name: OsString,
    identity: EntryIdentity,
}

#[derive(Debug, Clone)]
enum EntryIdentity {
    #[cfg(unix)]
    Unix {
        device: u64,
        inode: u64,
        file_type: u32,
    },
    #[cfg(windows)]
    Windows { file_id: [u8; 16], file_type: u32 },
}

#[cfg(unix)]
pub(super) fn entries(directory: &File, max_entries: usize) -> Result<Vec<EntryRecord>> {
    sorted_entries(unix::entries(directory, max_entries)?)
}

#[cfg(windows)]
pub(super) fn entries(directory: &File, max_entries: usize) -> Result<Vec<EntryRecord>> {
    sorted_entries(windows::entries(directory, max_entries)?)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn entries(_directory: &File, _max_entries: usize) -> Result<Vec<EntryRecord>> {
    anyhow::bail!("retained MCP directory enumeration is unsupported on this platform")
}

#[cfg(unix)]
pub(super) fn open_child(directory: &File, record: &EntryRecord) -> Result<File> {
    unix::open_child(directory, record)
}

#[cfg(windows)]
pub(super) fn open_child(directory: &File, record: &EntryRecord) -> Result<File> {
    windows::open_child(directory, record)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_child(_directory: &File, _record: &EntryRecord) -> Result<File> {
    anyhow::bail!("retained MCP directory entry opening is unsupported on this platform")
}

pub(super) fn verify_opened_entry(
    record: &EntryRecord,
    file: &File,
    path: &std::path::Path,
) -> Result<()> {
    let matches = opened_entry_matches(&record.identity, file)?;
    anyhow::ensure!(
        matches,
        "MCP directory entry changed after enumeration: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn opened_entry_matches(identity: &EntryIdentity, file: &File) -> Result<bool> {
    unix::opened_entry_matches(identity, file)
}

#[cfg(windows)]
fn opened_entry_matches(identity: &EntryIdentity, file: &File) -> Result<bool> {
    windows::opened_entry_matches(identity, file)
}

#[cfg(not(any(unix, windows)))]
fn opened_entry_matches(_identity: &EntryIdentity, _file: &File) -> Result<bool> {
    anyhow::bail!("retained MCP directory entry verification is unsupported on this platform")
}

fn ensure_capacity(observed: usize, max_entries: usize) -> Result<()> {
    anyhow::ensure!(
        observed < max_entries,
        "retained MCP directory exceeds the {max_entries}-entry limit"
    );
    Ok(())
}

fn sorted_entries(mut records: Vec<EntryRecord>) -> Result<Vec<EntryRecord>> {
    anyhow::ensure!(
        records.iter().all(|entry| is_single_component(&entry.name)),
        "retained MCP directory returned an invalid entry name"
    );
    records.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(records)
}

fn is_single_component(name: &std::ffi::OsStr) -> bool {
    let mut components = std::path::Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

pub(super) fn fingerprint<'a>(records: impl ExactSizeIterator<Item = &'a EntryRecord>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-mcp-directory-entry-set-v1\0");
    hasher.update(&(records.len() as u64).to_le_bytes());
    for record in records {
        let name = encoded_name(&record.name);
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(&name);
        record.identity.update_fingerprint(&mut hasher);
    }
    *hasher.finalize().as_bytes()
}

impl EntryIdentity {
    fn update_fingerprint(&self, hasher: &mut blake3::Hasher) {
        match self {
            #[cfg(unix)]
            Self::Unix {
                device,
                inode,
                file_type,
            } => {
                hasher.update(b"unix\0");
                hasher.update(&device.to_le_bytes());
                hasher.update(&inode.to_le_bytes());
                hasher.update(&file_type.to_le_bytes());
            }
            #[cfg(windows)]
            Self::Windows { file_id, file_type } => {
                hasher.update(b"windows\0");
                hasher.update(file_id);
                hasher.update(&file_type.to_le_bytes());
            }
        }
    }
}

#[cfg(unix)]
fn encoded_name(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(windows)]
fn encoded_name(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn encoded_name(name: &std::ffi::OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}
