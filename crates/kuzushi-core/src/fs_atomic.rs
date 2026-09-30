//! Crash-safe writes for `.kuzushi` state files.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(windows, test))]
#[path = "fs_atomic/replacement_retry.rs"]
mod replacement_retry;

#[cfg(test)]
use std::cell::RefCell;

/// Monotonic per-process counter so two concurrent `write_atomic` calls to the
/// *same* target never collide on their temp sibling. Process id alone is not
/// enough: a single process writing the same state file from two threads/tasks
/// would otherwise reuse one temp name and corrupt each other's write.
static TEMP_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicWriteFaultPoint {
    AfterTempSync,
    AfterRename,
}

#[cfg(test)]
thread_local! {
    static ATOMIC_WRITE_FAULT: RefCell<Option<(PathBuf, AtomicWriteFaultPoint)>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct AtomicWriteFaultGuard;

#[cfg(test)]
impl Drop for AtomicWriteFaultGuard {
    fn drop(&mut self) {
        ATOMIC_WRITE_FAULT.with(|fault| fault.borrow_mut().take());
    }
}

#[cfg(test)]
pub(crate) fn inject_atomic_write_fault(
    path: PathBuf,
    point: AtomicWriteFaultPoint,
) -> AtomicWriteFaultGuard {
    ATOMIC_WRITE_FAULT.with(|fault| {
        assert!(
            fault.borrow().is_none(),
            "atomic-write fault already installed"
        );
        *fault.borrow_mut() = Some((path, point));
    });
    AtomicWriteFaultGuard
}

/// Write `contents` to `path` atomically and durably.
///
/// Mechanism: write a uniquely-named same-directory temp sibling, `fsync` it,
/// then `rename` it over the target and `fsync` the parent directory. A crash
/// at any point leaves either the old file or the new file fully intact —
/// never a truncated or interleaved one.
///
/// Durability: `sync_all` on the temp flushes its bytes before the rename is
/// observable; the directory `fsync` persists the rename itself. Both are the
/// standard POSIX crash-safe write recipe.
///
/// Concurrency: temp names are collision-safe (pid + monotonic sequence +
/// nanos), so concurrent writers to one target proceed independently and the
/// last rename wins — a well-defined "last writer wins" with no torn state.
///
/// Platform note: Unix uses rename-replace semantics and requires the parent
/// directory sync to succeed. Windows uses `MoveFileExW` with
/// replace-existing and write-through; its additional directory sync remains
/// best-effort because ordinary directory handles are not portable there.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    write_atomic_bytes(path, contents.as_bytes())
}

pub(crate) fn write_atomic_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let temp = temp_sibling(path);
    write_and_sync_temp(&temp, contents)
        .with_context(|| format!("Could not write {}", temp.display()))?;
    #[cfg(test)]
    trigger_atomic_write_fault(path, AtomicWriteFaultPoint::AfterTempSync)?;
    if let Err(error) = replace_file(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("Could not move {} into place", path.display()));
    }
    #[cfg(test)]
    trigger_atomic_write_fault(path, AtomicWriteFaultPoint::AfterRename)?;
    sync_parent_dir(path).with_context(|| format!("Could not sync parent of {}", path.display()))
}

#[cfg(test)]
fn trigger_atomic_write_fault(path: &Path, point: AtomicWriteFaultPoint) -> Result<()> {
    let triggered = ATOMIC_WRITE_FAULT.with(|fault| {
        let matches = fault
            .borrow()
            .as_ref()
            .is_some_and(|(target, selected)| paths_match(target, path) && *selected == point);
        matches.then(|| fault.borrow_mut().take()).is_some()
    });
    anyhow::ensure!(
        !triggered,
        "injected crash after {point:?} for {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
fn paths_match(left: &Path, right: &Path) -> bool {
    left == right || normalized_test_path(left) == normalized_test_path(right)
}

#[cfg(test)]
fn normalized_test_path(path: &Path) -> PathBuf {
    let Some(parent) = path.parent() else {
        return path.to_path_buf();
    };
    let normalized_parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    path.file_name()
        .map(|name| normalized_parent.join(name))
        .unwrap_or(normalized_parent)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    replacement_retry::replace_with_retry(|| {
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

/// Write the full contents to `temp` and flush them to stable storage before
/// the caller renames it into place.
fn write_and_sync_temp(temp: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = create_temp_file(temp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn create_temp_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn create_temp_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
}

/// Persist the directory entry created by the rename.
#[cfg(unix)]
pub(crate) fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub(crate) fn slug(value: &str, fallback: &str, max_parts: usize) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .take(max_parts)
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        fallback.to_string()
    } else {
        slug
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let seq = TEMP_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!(
        ".{file_name}.tmp-{}-{seq}-{nanos}",
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file_and_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, "{\"v\":1}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"v\":1}");
        write_atomic(&path, "{\"v\":2}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"v\":2}");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/state.json");
        write_atomic(&path, "ok").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "ok");
    }

    #[test]
    fn leaves_no_temp_sibling_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, "ok").unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn concurrent_same_process_writes_never_tear_or_leak_temps() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("state.json"));

        // Every writer writes a distinct, self-consistent payload. Because temp
        // siblings are collision-safe, the final file must be exactly one of
        // them — never a byte-level interleaving of two.
        let mut handles = Vec::new();
        for writer in 0..16 {
            let path = Arc::clone(&path);
            handles.push(thread::spawn(move || {
                let payload = format!("{{\"writer\":{writer}}}");
                for _ in 0..25 {
                    write_atomic(&path, &payload).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let contents = fs::read_to_string(path.as_path()).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&contents).expect("final file must be one intact payload");
        assert!(value.get("writer").and_then(|w| w.as_u64()).is_some());

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "no temp siblings should remain");
    }
}
