use crate::scan::ScanCancellation;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
pub(crate) struct RegularFileWalkOptions {
    pub operation: &'static str,
    pub max_entries: usize,
    pub max_files: usize,
    pub max_depth: usize,
    pub file_limit: FileLimitBehavior,
    pub ignored_dir: fn(&Path) -> bool,
}

#[derive(Clone, Copy)]
pub(crate) enum FileLimitBehavior {
    Error,
    Stop,
}

#[derive(Debug)]
pub(crate) struct RegularFileInventory {
    pub files: Vec<PathBuf>,
    pub truncated: bool,
}

#[derive(Default)]
struct WalkBudget {
    entries: usize,
    files: usize,
}

pub(crate) fn collect_regular_files(
    root: &Path,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
) -> Result<RegularFileInventory> {
    let mut files = Vec::new();
    let mut budget = WalkBudget::default();
    let truncated = walk_dir(root, 0, cancellation, options, &mut budget, &mut files)?;
    Ok(RegularFileInventory { files, truncated })
}

fn walk_dir(
    dir: &Path,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<bool> {
    check_cancellation(cancellation, options.operation)?;
    let entries = read_sorted_entries(dir, cancellation, options, budget)?;
    for entry in entries {
        if visit_entry(entry, depth, cancellation, options, budget, files)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_sorted_entries(
    dir: &Path,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &WalkBudget,
) -> Result<Vec<fs::DirEntry>> {
    let remaining = options.max_entries.saturating_sub(budget.entries);
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("{}: read {}", options.operation, dir.display()))?;
    let mut entries = collect_entries(
        read_dir.take(remaining.saturating_add(1)),
        cancellation,
        options.operation,
    )?;
    anyhow::ensure!(
        entries.len() <= remaining,
        "{} exceeded the {}-entry traversal limit at {}",
        options.operation,
        options.max_entries,
        dir.display()
    );
    entries.sort_by_key(fs::DirEntry::path);
    Ok(entries)
}

fn collect_entries<T>(
    entries: impl Iterator<Item = std::io::Result<T>>,
    cancellation: &ScanCancellation,
    operation: &str,
) -> Result<Vec<T>> {
    let mut collected = Vec::new();
    for entry in entries {
        cancellation.wait_if_paused();
        check_cancellation(cancellation, operation)?;
        collected.push(entry?);
    }
    Ok(collected)
}

fn visit_entry(
    entry: fs::DirEntry,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<bool> {
    cancellation.wait_if_paused();
    check_cancellation(cancellation, options.operation)?;
    record_entry(budget, options, &entry.path())?;
    let file_type = entry.file_type()?;
    if file_type.is_file() {
        return record_file(entry.path(), budget, options, files);
    }
    if file_type.is_dir() && !(options.ignored_dir)(&entry.path()) {
        return descend(entry.path(), depth, cancellation, options, budget, files);
    }
    Ok(false)
}

fn record_entry(
    budget: &mut WalkBudget,
    options: RegularFileWalkOptions,
    path: &Path,
) -> Result<()> {
    budget.entries = budget.entries.saturating_add(1);
    anyhow::ensure!(
        budget.entries <= options.max_entries,
        "{} exceeded the {}-entry traversal limit at {}",
        options.operation,
        options.max_entries,
        path.display()
    );
    Ok(())
}

fn record_file(
    path: PathBuf,
    budget: &mut WalkBudget,
    options: RegularFileWalkOptions,
    files: &mut Vec<PathBuf>,
) -> Result<bool> {
    if budget.files >= options.max_files {
        return match options.file_limit {
            FileLimitBehavior::Error => anyhow::bail!(
                "{} exceeded the {}-file traversal limit at {}",
                options.operation,
                options.max_files,
                path.display()
            ),
            FileLimitBehavior::Stop => Ok(true),
        };
    }
    budget.files = budget.files.saturating_add(1);
    files.push(path);
    Ok(false)
}

fn descend(
    path: PathBuf,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<bool> {
    let next_depth = depth.saturating_add(1);
    anyhow::ensure!(
        next_depth <= options.max_depth,
        "{} exceeded the {}-level traversal limit at {}",
        options.operation,
        options.max_depth,
        path.display()
    );
    walk_dir(
        &path,
        next_depth,
        cancellation,
        options,
        budget,
        files,
    )
}

fn check_cancellation(cancellation: &ScanCancellation, operation: &str) -> Result<()> {
    anyhow::ensure!(!cancellation.is_cancelled(), "{operation} scan cancelled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> RegularFileWalkOptions {
        RegularFileWalkOptions {
            operation: "bounded-walk-test",
            max_entries: 10,
            max_files: 10,
            max_depth: 2,
            file_limit: FileLimitBehavior::Error,
            ignored_dir: |_| false,
        }
    }

    #[test]
    fn returns_regular_files_in_deterministic_order() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("z.txt"), "z").unwrap();
        fs::write(temp.path().join("a.txt"), "a").unwrap();

        let inventory =
            collect_regular_files(temp.path(), &ScanCancellation::default(), options()).unwrap();

        assert_eq!(
            inventory.files,
            vec![temp.path().join("a.txt"), temp.path().join("z.txt")]
        );
        assert!(!inventory.truncated);
    }

    #[test]
    fn rejects_entry_and_depth_exhaustion() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a"), "a").unwrap();
        fs::write(temp.path().join("b"), "b").unwrap();
        let mut entry_limited = options();
        entry_limited.max_entries = 1;
        assert!(collect_regular_files(
            temp.path(),
            &ScanCancellation::default(),
            entry_limited
        )
        .unwrap_err()
        .to_string()
        .contains("entry traversal limit"));

        let nested = temp.path().join("one").join("two");
        fs::create_dir_all(&nested).unwrap();
        let mut depth_limited = options();
        depth_limited.max_depth = 1;
        assert!(collect_regular_files(
            temp.path(),
            &ScanCancellation::default(),
            depth_limited
        )
        .unwrap_err()
        .to_string()
        .contains("level traversal limit"));
    }

    #[test]
    fn observes_cancellation_before_enumerating() {
        let temp = tempfile::tempdir().unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let error = collect_regular_files(temp.path(), &cancellation, options()).unwrap_err();

        assert!(error.to_string().contains("scan cancelled"));
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks() {
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), target.path().join("linked")).unwrap();

        let inventory = collect_regular_files(
            target.path(),
            &ScanCancellation::default(),
            options(),
        )
        .unwrap();

        assert!(inventory.files.is_empty());
    }

    #[test]
    fn stop_limit_returns_first_files_and_discloses_truncation() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("c"), "c").unwrap();
        fs::write(temp.path().join("a"), "a").unwrap();
        fs::write(temp.path().join("b"), "b").unwrap();
        let mut limited = options();
        limited.max_files = 2;
        limited.file_limit = FileLimitBehavior::Stop;

        let inventory =
            collect_regular_files(temp.path(), &ScanCancellation::default(), limited).unwrap();

        assert_eq!(
            inventory.files,
            vec![temp.path().join("a"), temp.path().join("b")]
        );
        assert!(inventory.truncated);
    }

    #[test]
    fn cancellation_is_checked_while_entries_are_consumed() {
        let cancellation = ScanCancellation::default();
        let requester = cancellation.clone();
        let mut yielded = 0;
        let entries = std::iter::from_fn(move || {
            yielded += 1;
            if yielded == 3 {
                requester.cancel();
            }
            Some(Ok(yielded))
        });

        let error = collect_entries(entries, &cancellation, "enumeration-test").unwrap_err();

        assert!(error.to_string().contains("scan cancelled"));
    }
}
