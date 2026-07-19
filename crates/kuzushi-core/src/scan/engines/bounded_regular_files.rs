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
    pub ignored_dir: fn(&Path) -> bool,
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
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut budget = WalkBudget::default();
    walk_dir(root, 0, cancellation, options, &mut budget, &mut files)?;
    Ok(files)
}

fn walk_dir(
    dir: &Path,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    check_cancellation(cancellation, options.operation)?;
    let entries = read_sorted_entries(dir, options, budget)?;
    for entry in entries {
        visit_entry(entry, depth, cancellation, options, budget, files)?;
    }
    Ok(())
}

fn read_sorted_entries(
    dir: &Path,
    options: RegularFileWalkOptions,
    budget: &WalkBudget,
) -> Result<Vec<fs::DirEntry>> {
    let remaining = options.max_entries.saturating_sub(budget.entries);
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("{}: read {}", options.operation, dir.display()))?
        .take(remaining.saturating_add(1))
        .collect::<std::io::Result<Vec<_>>>()?;
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

fn visit_entry(
    entry: fs::DirEntry,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    cancellation.wait_if_paused();
    check_cancellation(cancellation, options.operation)?;
    record_entry(budget, options, &entry.path())?;
    let file_type = entry.file_type()?;
    if file_type.is_file() {
        return record_file(entry.path(), budget, options, files);
    }
    if file_type.is_dir() && !(options.ignored_dir)(&entry.path()) {
        descend(entry.path(), depth, cancellation, options, budget, files)?;
    }
    Ok(())
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
) -> Result<()> {
    budget.files = budget.files.saturating_add(1);
    anyhow::ensure!(
        budget.files <= options.max_files,
        "{} exceeded the {}-file traversal limit at {}",
        options.operation,
        options.max_files,
        path.display()
    );
    files.push(path);
    Ok(())
}

fn descend(
    path: PathBuf,
    depth: usize,
    cancellation: &ScanCancellation,
    options: RegularFileWalkOptions,
    budget: &mut WalkBudget,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
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
            ignored_dir: |_| false,
        }
    }

    #[test]
    fn returns_regular_files_in_deterministic_order() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("z.txt"), "z").unwrap();
        fs::write(temp.path().join("a.txt"), "a").unwrap();

        let files = collect_regular_files(temp.path(), &ScanCancellation::default(), options())
            .unwrap();

        assert_eq!(
            files,
            vec![temp.path().join("a.txt"), temp.path().join("z.txt")]
        );
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

        let files = collect_regular_files(
            target.path(),
            &ScanCancellation::default(),
            options(),
        )
        .unwrap();

        assert!(files.is_empty());
    }
}
