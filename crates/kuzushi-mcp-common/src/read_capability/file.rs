use super::open::identity_for;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReadFileIdentity {
    pub len: u64,
    pub modified_nanos: Option<u128>,
    #[cfg(unix)]
    pub device: u64,
    #[cfg(unix)]
    pub inode: u64,
    #[cfg(unix)]
    pub change_seconds: i64,
    #[cfg(unix)]
    pub change_nanos: i64,
    #[cfg(windows)]
    pub volume_serial_number: u64,
    #[cfg(windows)]
    pub file_id: [u8; 16],
    #[cfg(windows)]
    pub change_time: i64,
    pub content_sha256: Option<[u8; 32]>,
}

impl ReadFileIdentity {
    pub fn requires_content_digest(&self) -> bool {
        #[cfg(unix)]
        {
            false
        }
        #[cfg(windows)]
        {
            // A nonzero NTFS timestamp is still not a content identity.
            true
        }
        #[cfg(not(any(unix, windows)))]
        {
            true
        }
    }

    fn bind_content_digest(mut self, bytes: &[u8]) -> Self {
        if self.requires_content_digest() {
            self.content_sha256 = Some(Sha256::digest(bytes).into());
        }
        self
    }

    fn bind_digest(mut self, digest: [u8; 32]) -> Self {
        if self.requires_content_digest() {
            self.content_sha256 = Some(digest);
        }
        self
    }

    pub(super) fn same_file_object(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(windows)]
        {
            self.volume_serial_number == other.volume_serial_number && self.file_id == other.file_id
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.modified_nanos == other.modified_nanos && self.len == other.len
        }
    }
}

#[derive(Debug)]
pub struct BoundedReadFile {
    path: PathBuf,
    file: File,
    identity: ReadFileIdentity,
    max_bytes: usize,
    #[cfg(windows)]
    opening_digest: [u8; 32],
}

impl BoundedReadFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> &ReadFileIdentity {
        &self.identity
    }

    pub fn verify_unchanged(&self) -> Result<()> {
        let metadata = self.file.metadata()?;
        let current = identity_for(&self.file, &metadata)?;
        anyhow::ensure!(
            current == self.identity,
            "MCP file changed after it was opened: {}",
            self.path.display()
        );
        self.verify_content_digest(None)
    }

    pub fn read_bytes_with_identity(mut self) -> Result<(Vec<u8>, ReadFileIdentity)> {
        let read_limit = self
            .max_bytes
            .checked_add(1)
            .context("MCP read limit is too large")?;
        let mut bytes = Vec::with_capacity(read_limit.min(64 * 1024));
        Read::by_ref(&mut self.file)
            .take(read_limit as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("could not read {}", self.path.display()))?;
        ensure_size(&self.path, bytes.len(), self.max_bytes)?;
        self.verify_after_read(&bytes)?;
        let identity = self.identity.bind_content_digest(&bytes);
        Ok((bytes, identity))
    }

    pub fn read_bytes(self) -> Result<Vec<u8>> {
        self.read_bytes_with_identity().map(|(bytes, _)| bytes)
    }

    pub fn read_utf8(self) -> Result<String> {
        let path = self.path.clone();
        String::from_utf8(self.read_bytes()?)
            .with_context(|| format!("MCP file is not valid UTF-8: {}", path.display()))
    }

    pub fn copy_to_with_sha256_hex(mut self, writer: &mut impl Write) -> Result<String> {
        let digest = self.stream_chunks(|bytes| writer.write_all(bytes).map_err(Into::into))?;
        Ok(hex_digest(&digest))
    }

    /// Stream this authorized file through a bounded callback while retaining
    /// the same before/after identity checks as the ordinary read helpers.
    pub fn for_each_chunk(mut self, consume: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.stream_chunks(consume).map(|_| ())
    }

    fn stream_chunks(&mut self, mut consume: impl FnMut(&[u8]) -> Result<()>) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        let mut copied = 0_usize;
        let mut buffer = [0_u8; 64 * 1024];
        while let read @ 1.. = self.file.read(&mut buffer)? {
            copied = copied.checked_add(read).context("MCP copy size overflow")?;
            ensure_size(&self.path, copied, self.max_bytes)?;
            consume(&buffer[..read])?;
            hasher.update(&buffer[..read]);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        self.verify_after_copy(digest)?;
        Ok(digest)
    }

    fn verify_after_copy(&self, digest: [u8; 32]) -> Result<()> {
        let metadata = self.file.metadata()?;
        let after = identity_for(&self.file, &metadata)?.bind_digest(digest);
        let before = self.identity.clone().bind_digest(digest);
        anyhow::ensure!(
            after == before,
            "MCP file changed while it was being copied: {}",
            self.path.display()
        );
        self.verify_content_digest(Some(digest))
    }

    fn verify_after_read(&self, bytes: &[u8]) -> Result<()> {
        let metadata = self.file.metadata()?;
        let current = identity_for(&self.file, &metadata)?;
        anyhow::ensure!(
            current == self.identity,
            "MCP file changed while it was being read: {}",
            self.path.display()
        );
        self.verify_content_bytes(bytes)
    }

    fn verify_content_bytes(&self, bytes: &[u8]) -> Result<()> {
        #[cfg(windows)]
        {
            self.verify_content_digest(Some(Sha256::digest(bytes).into()))
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Ok(())
        }
    }

    #[cfg(windows)]
    fn verify_content_digest(&self, read_digest: Option<[u8; 32]>) -> Result<()> {
        let current = windows_digest(&self.file, self.max_bytes)?;
        anyhow::ensure!(
            current == self.opening_digest && read_digest.unwrap_or(current) == self.opening_digest,
            "MCP file changed while it was being read: {}",
            self.path.display()
        );
        Ok(())
    }

    #[cfg(not(windows))]
    fn verify_content_digest(&self, _read_digest: Option<[u8; 32]>) -> Result<()> {
        Ok(())
    }
}

pub(super) fn bounded_regular_file(
    path: PathBuf,
    file: File,
    max_bytes: usize,
) -> Result<BoundedReadFile> {
    let metadata = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "MCP path is not a regular file: {}",
        path.display()
    );
    ensure_size(&path, metadata.len() as usize, max_bytes)?;
    Ok(BoundedReadFile {
        path,
        identity: identity_for(&file, &metadata)?,
        #[cfg(windows)]
        opening_digest: windows_digest(&file, max_bytes)?,
        file,
        max_bytes,
    })
}

#[cfg(windows)]
fn windows_digest(file: &File, max_bytes: usize) -> Result<[u8; 32]> {
    use std::io::{Seek, SeekFrom};
    let mut borrowed = file;
    let position = borrowed.stream_position()?;
    let result = windows_digest_from_start(file, max_bytes);
    borrowed.seek(SeekFrom::Start(position))?;
    result
}

#[cfg(windows)]
fn windows_digest_from_start(file: &File, max_bytes: usize) -> Result<[u8; 32]> {
    use std::os::windows::fs::FileExt;
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while let read @ 1.. = file.seek_read(&mut buffer, offset)? {
        offset = offset
            .checked_add(read as u64)
            .context("MCP digest size overflow")?;
        anyhow::ensure!(
            offset <= max_bytes as u64,
            "MCP file exceeds its bounded digest limit"
        );
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

fn ensure_size(path: &Path, size: usize, max_bytes: usize) -> Result<()> {
    anyhow::ensure!(
        size <= max_bytes,
        "MCP file exceeds the maximum supported size of {max_bytes} bytes: {}",
        path.display()
    );
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
