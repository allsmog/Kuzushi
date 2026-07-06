//! Crash-safe writes for `.kuzushi` state files.

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Monotonic per-process counter so two concurrent `write_atomic` calls to the
/// *same* target never collide on their temp sibling. Process id alone is not
/// enough: a single process writing the same state file from two threads/tasks
/// would otherwise reuse one temp name and corrupt each other's write.
static TEMP_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

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
/// Platform note: relies on POSIX rename-replace semantics (atomic overwrite
/// of an existing destination on the same filesystem). This is the target
/// platform for `.kuzushi` state; the directory `fsync` is best-effort and
/// silently skipped where opening a directory handle is not supported.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> Result<()> {
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
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("Could not move {} into place", path.display()));
    }
    sync_parent_dir(path);
    Ok(())
}

/// Write the full contents to `temp` and flush them to stable storage before
/// the caller renames it into place.
fn write_and_sync_temp(temp: &Path, contents: &str) -> std::io::Result<()> {
    let mut file = fs::File::create(temp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Persist the directory entry created by the rename. Best-effort: on
/// platforms that do not allow opening a directory as a file this is a no-op,
/// which does not weaken the atomicity of the rename itself.
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

pub(crate) fn load_jsonl<T>(path: &Path, item_label: &str) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not read {}", path.display()))
        }
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<T>(line)
                .with_context(|| format!("Could not parse {item_label} line {}", index + 1))
        })
        .collect()
}

pub(crate) fn save_jsonl<T>(path: &Path, values: &[T], item_label: &str) -> Result<()>
where
    T: Serialize,
{
    let mut lines = Vec::with_capacity(values.len());
    for value in values {
        lines.push(
            serde_json::to_string(value)
                .with_context(|| format!("Could not serialize {item_label}"))?,
        );
    }
    let contents = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    write_atomic(path, &contents)
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
