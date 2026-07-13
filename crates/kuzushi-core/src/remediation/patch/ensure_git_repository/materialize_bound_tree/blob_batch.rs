use super::manifest::{BoundTreeEntry, BoundTreeManifest};
use super::*;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};

const BATCH_HEADER_LIMIT: usize = 256;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn extract_blob_batch(
    batch: &mut File,
    checkout: &Path,
    manifest: &BoundTreeManifest,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let mut reader = BufReader::new(batch);
    for entry in &manifest.entries {
        ensure_materialization_active(control, deadline)?;
        let header = read_batch_header(&mut reader)?;
        validate_batch_header(&header, entry)?;
        write_blob_file(&mut reader, checkout, entry, control, deadline)?;
        read_blob_delimiter(&mut reader)?;
    }
    ensure_batch_eof(&mut reader)
}

fn read_batch_header(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .context("patch:finding could not read bound blob header")?;
        anyhow::ensure!(
            !available.is_empty(),
            "patch:finding bound blob batch ended before its header"
        );
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        anyhow::ensure!(
            header.len() + count <= BATCH_HEADER_LIMIT,
            "patch:finding bound blob batch header exceeded its limit"
        );
        header.extend_from_slice(&available[..count]);
        reader.consume(count);
        if header.ends_with(b"\n") {
            header.pop();
            return Ok(header);
        }
    }
}

fn validate_batch_header(header: &[u8], entry: &BoundTreeEntry) -> Result<()> {
    let header = std::str::from_utf8(header)
        .context("patch:finding bound blob batch header was not UTF-8")?;
    let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(
        fields.len() == 3,
        "patch:finding bound blob batch header had an invalid shape"
    );
    anyhow::ensure!(
        fields[0] == entry.oid && fields[1] == "blob",
        "patch:finding bound blob batch returned the wrong object"
    );
    let size = fields[2]
        .parse::<u64>()
        .context("patch:finding bound blob batch returned an invalid size")?;
    anyhow::ensure!(
        size == entry.size,
        "patch:finding bound blob batch size changed after preflight"
    );
    Ok(())
}

fn write_blob_file(
    reader: &mut impl Read,
    checkout: &Path,
    entry: &BoundTreeEntry,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let path = prepare_blob_path(checkout, &entry.relative_path)?;
    let mut file = open_blob_file(&path)?;
    copy_exact_blob(reader, &mut file, entry.size, control, deadline)?;
    set_blob_permissions(&path, entry.executable())?;
    Ok(())
}

fn prepare_blob_path(checkout: &Path, relative: &Path) -> Result<PathBuf> {
    if let Some(parent) = relative
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        crate::workspace::ensure_workspace_output_dir(checkout, parent)?;
    }
    crate::workspace::prepare_workspace_output_path(checkout, relative)
}

#[cfg(unix)]
fn open_blob_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("patch:finding could not create {}", path.display()))
}

#[cfg(windows)]
fn open_blob_file(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("patch:finding could not create {}", path.display()))
}

#[cfg(not(any(unix, windows)))]
fn open_blob_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("patch:finding could not create {}", path.display()))
}

fn copy_exact_blob(
    reader: &mut impl Read,
    writer: &mut File,
    size: u64,
    control: PatchCommandControl<'_>,
    deadline: Instant,
) -> Result<()> {
    let mut remaining = size;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        ensure_materialization_active(control, deadline)?;
        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        reader
            .read_exact(&mut buffer[..count])
            .context("patch:finding bound blob batch ended inside an object")?;
        writer
            .write_all(&buffer[..count])
            .context("patch:finding could not write a bound tree file")?;
        remaining -= count as u64;
    }
    writer
        .flush()
        .context("patch:finding could not flush a bound tree file")
}

#[cfg(unix)]
fn set_blob_permissions(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("patch:finding could not set mode on {}", path.display()))
}

#[cfg(not(unix))]
fn set_blob_permissions(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

fn read_blob_delimiter(reader: &mut impl Read) -> Result<()> {
    let mut delimiter = [0_u8; 1];
    reader
        .read_exact(&mut delimiter)
        .context("patch:finding bound blob batch omitted an object delimiter")?;
    anyhow::ensure!(
        delimiter == [b'\n'],
        "patch:finding bound blob batch used an invalid object delimiter"
    );
    Ok(())
}

fn ensure_batch_eof(reader: &mut impl Read) -> Result<()> {
    let mut trailing = [0_u8; 1];
    anyhow::ensure!(
        reader
            .read(&mut trailing)
            .context("patch:finding could not finish bound blob batch")?
            == 0,
        "patch:finding bound blob batch contained duplicate or trailing data"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    use std::time::Duration;

    fn entry() -> BoundTreeEntry {
        BoundTreeEntry {
            mode: "100644".to_string(),
            oid: "1111111111111111111111111111111111111111".to_string(),
            size: 4,
            git_path: "demo.txt".to_string(),
            relative_path: PathBuf::from("demo.txt"),
        }
    }

    fn manifest() -> BoundTreeManifest {
        BoundTreeManifest {
            source_commit: "2222222222222222222222222222222222222222".to_string(),
            tree_oid: "3333333333333333333333333333333333333333".to_string(),
            commit_body: b"tree 3333333333333333333333333333333333333333\n\nmsg\n".to_vec(),
            entries: vec![entry()],
            batch_output_bound: 128,
        }
    }

    fn batch_file(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file
    }

    fn control() -> PatchCommandControl<'static> {
        PatchCommandControl::unattended(Duration::from_secs(5))
    }

    fn valid_batch() -> Vec<u8> {
        format!("{} blob 4\ndata\n", entry().oid).into_bytes()
    }

    #[test]
    fn exact_batch_writes_the_bound_blob() {
        let checkout = tempfile::tempdir().unwrap();
        let mut batch = batch_file(&valid_batch());
        let control = control();
        let deadline = control.deadline("fixture").unwrap();

        extract_blob_batch(&mut batch, checkout.path(), &manifest(), control, deadline).unwrap();

        assert_eq!(
            std::fs::read(checkout.path().join("demo.txt")).unwrap(),
            b"data"
        );
    }

    #[test]
    fn short_wrong_and_trailing_batches_fail_closed() {
        let wrong_oid = format!("{} blob 4\ndata\n", "9".repeat(40));
        let mut trailing = valid_batch();
        trailing.extend(valid_batch());
        for bytes in [
            format!("{} blob 4\nda", entry().oid).into_bytes(),
            wrong_oid.into_bytes(),
            trailing,
        ] {
            let checkout = tempfile::tempdir().unwrap();
            let mut batch = batch_file(&bytes);
            let control = control();
            let deadline = control.deadline("fixture").unwrap();
            assert!(extract_blob_batch(
                &mut batch,
                checkout.path(),
                &manifest(),
                control,
                deadline
            )
            .is_err());
        }
    }

    #[test]
    fn expired_deadline_refuses_before_writing() {
        let checkout = tempfile::tempdir().unwrap();
        let mut batch = batch_file(&valid_batch());

        let error = extract_blob_batch(
            &mut batch,
            checkout.path(),
            &manifest(),
            control(),
            Instant::now(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("deadline"), "{error}");
        assert!(!checkout.path().join("demo.txt").exists());
    }
}
