//! One bounded iterative source walk for hash-only identity and blob indexing.
use super::{should_ignore_path, MAX_INDEXED_FILE_BYTES};
use anyhow::{Context, Result};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub(super) const MAX_SOURCE_TREE_ENTRIES: usize = 1_000_000;

pub(super) enum SourceWalkEvent {
    File(PathBuf),
    Progress,
}

struct SourceWalk {
    root: PathBuf,
    pending: Vec<PathBuf>,
    visited: BTreeSet<PathBuf>,
    entries: usize,
    maximum: usize,
}

pub(super) fn walk_source_files(
    root: &Path,
    canceled: &dyn Fn() -> bool,
    visit: &mut dyn FnMut(SourceWalkEvent) -> Result<()>,
) -> Result<()> {
    walk_with_limit(root, MAX_SOURCE_TREE_ENTRIES, canceled, visit)
}

fn walk_with_limit(
    root: &Path,
    maximum: usize,
    canceled: &dyn Fn() -> bool,
    visit: &mut dyn FnMut(SourceWalkEvent) -> Result<()>,
) -> Result<()> {
    let root = root
        .canonicalize()
        .context("Could not resolve source root")?;
    let mut walk = SourceWalk {
        pending: vec![root.clone()],
        root,
        visited: BTreeSet::new(),
        entries: 0,
        maximum,
    };
    while let Some(directory) = walk.pending.pop() {
        check_cancellation(canceled)?;
        let entries = walk.open_directory(&directory)?;
        visit(SourceWalkEvent::Progress)?;
        for entry in entries {
            check_cancellation(canceled)?;
            walk.record_entry()?;
            visit(walk.route_entry(entry?)?)?;
        }
    }
    check_cancellation(canceled)
}

impl SourceWalk {
    fn record_entry(&mut self) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        anyhow::ensure!(self.entries <= self.maximum,
            "source traversal exceeds the {}-entry safety limit; no complete source identity was produced", self.maximum);
        Ok(())
    }

    fn open_directory(&mut self, directory: &Path) -> Result<fs::ReadDir> {
        let metadata = fs::symlink_metadata(directory)?;
        anyhow::ensure!(
            metadata.is_dir(),
            "source directory changed or became a symlink: {}",
            directory.display()
        );
        let canonical = self.contained_path(directory)?;
        anyhow::ensure!(
            self.visited.insert(canonical),
            "source directory was visited twice: {}",
            directory.display()
        );
        fs::read_dir(directory).with_context(|| format!("Could not read {}", directory.display()))
    }

    fn contained_path(&self, path: &Path) -> Result<PathBuf> {
        let canonical = path.canonicalize()?;
        anyhow::ensure!(
            canonical.starts_with(&self.root),
            "source path escaped the repository: {}",
            path.display()
        );
        Ok(canonical)
    }

    fn route_entry(&mut self, entry: fs::DirEntry) -> Result<SourceWalkEvent> {
        let path = entry.path();
        if should_ignore_path(path.strip_prefix(&self.root)?) {
            return Ok(SourceWalkEvent::Progress);
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            self.pending.push(path);
            return Ok(SourceWalkEvent::Progress);
        }
        if kind.is_file() {
            return self.file_event(&entry);
        }
        Ok(SourceWalkEvent::Progress)
    }

    fn file_event(&self, entry: &fs::DirEntry) -> Result<SourceWalkEvent> {
        if entry.metadata()?.len() > MAX_INDEXED_FILE_BYTES {
            return Ok(SourceWalkEvent::Progress);
        }
        let path = entry.path();
        self.contained_path(&path)?;
        Ok(SourceWalkEvent::File(path))
    }
}

pub(super) fn check_cancellation(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(
        !canceled(),
        "source identity was canceled; no complete source identity was produced"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
