//! Bounded lexical depth-first traversal without recursive Rust calls.
use super::*;

enum Pending {
    Directory(PathBuf),
    Entry(fs::DirEntry),
}

pub(super) fn collect(
    root: &Path,
    dir: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
    files: &mut Vec<PathBuf>,
    gaps: &mut CoverageGaps,
) -> Result<usize> {
    let mut pending = vec![Pending::Directory(dir.into())];
    let mut inspected = 0;
    while let Some(item) = pending.pop() {
        anyhow::ensure!(
            !cancellation.is_cancelled(),
            "secret-scan scan cancelled during traversal"
        );
        match item {
            Pending::Directory(path) => {
                let entries = entries(
                    root,
                    &path,
                    options.max_entries,
                    &mut inspected,
                    cancellation,
                    gaps,
                )?;
                pending.extend(entries.into_iter().rev().map(Pending::Entry));
            }
            Pending::Entry(entry) => visit_entry(root, entry, options, &mut pending, files, gaps),
        }
    }
    Ok(inspected)
}

fn entries(
    root: &Path,
    path: &Path,
    maximum: usize,
    inspected: &mut usize,
    cancellation: &ScanCancellation,
    gaps: &mut CoverageGaps,
) -> Result<Vec<fs::DirEntry>> {
    if *inspected >= maximum {
        limit_gap(root, path, maximum, gaps);
        return Ok(Vec::new());
    }
    let reader = match crate::bounded_file::read_dir_within(root, path) {
        Ok(reader) => reader,
        Err(error) => {
            gaps.record(root, path, CoverageGapKind::Directory, &error);
            return Ok(Vec::new());
        }
    };
    read_entries(root, path, reader, maximum, inspected, cancellation, gaps)
}

fn read_entries(
    root: &Path,
    path: &Path,
    reader: fs::ReadDir,
    maximum: usize,
    inspected: &mut usize,
    cancellation: &ScanCancellation,
    gaps: &mut CoverageGaps,
) -> Result<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in reader.take(maximum - *inspected) {
        anyhow::ensure!(
            !cancellation.is_cancelled(),
            "secret-scan scan cancelled during traversal"
        );
        *inspected += 1;
        record_entry(root, path, entry, &mut entries, gaps);
    }
    if *inspected >= maximum {
        limit_gap(root, path, maximum, gaps);
    }
    entries.sort_by_key(|entry| entry.path());
    Ok(entries)
}

fn record_entry(
    root: &Path,
    path: &Path,
    entry: std::io::Result<fs::DirEntry>,
    entries: &mut Vec<fs::DirEntry>,
    gaps: &mut CoverageGaps,
) {
    match entry {
        Ok(entry) => entries.push(entry),
        Err(error) => gaps.record(root, path, CoverageGapKind::Entry, &error),
    }
}

fn visit_entry(
    root: &Path,
    entry: fs::DirEntry,
    options: &SecretScanOptions,
    pending: &mut Vec<Pending>,
    files: &mut Vec<PathBuf>,
    gaps: &mut CoverageGaps,
) {
    let kind = match entry.file_type() {
        Ok(kind) => kind,
        Err(error) => {
            gaps.record(root, &entry.path(), CoverageGapKind::Entry, &error);
            return;
        }
    };
    if kind.is_dir() {
        queue_directory(entry, options, pending);
    } else if kind.is_file() {
        files.push(entry.path());
    }
}

fn queue_directory(entry: fs::DirEntry, options: &SecretScanOptions, pending: &mut Vec<Pending>) {
    if !options
        .exclude_dirs
        .contains(entry.file_name().to_string_lossy().as_ref())
    {
        pending.push(Pending::Directory(entry.path()));
    }
}

fn limit_gap(root: &Path, path: &Path, maximum: usize, gaps: &mut CoverageGaps) {
    gaps.record(
        root,
        path,
        CoverageGapKind::Directory,
        &std::io::Error::other(format!(
            "entry allowance reached ({maximum}); remaining directory entries were not inspected"
        )),
    );
}

#[cfg(test)]
mod tests;
