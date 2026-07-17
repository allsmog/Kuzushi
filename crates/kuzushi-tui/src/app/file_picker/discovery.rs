use super::*;
use std::collections::BinaryHeap;
use std::fs;

pub(super) const FILE_PICKER_ENTRY_VISIT_LIMIT: usize = 100_000;
pub(super) const FILE_PICKER_MAX_DEPTH: usize = 32;
pub(super) const FILE_PICKER_PATH_BYTE_LIMIT: usize = 8 * 1024 * 1024;
pub(super) const FILE_PICKER_DIRECTORY_CHUNK: usize = 128;

pub(crate) fn workspace_file_candidates(root: &Path, limit: usize) -> FileCompletionIndex {
    workspace_file_candidates_cancellable(root, limit, || false).unwrap_or_default()
}

pub(crate) fn workspace_file_candidates_cancellable(
    root: &Path,
    limit: usize,
    is_canceled: impl Fn() -> bool,
) -> Option<FileCompletionIndex> {
    let budget = FileDiscoveryBudget::new(limit);
    FileDiscovery::new(root, budget).run(is_canceled)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FileDiscoveryBudget {
    pub(super) retained_results: usize,
    pub(super) entry_visits: usize,
    pub(super) depth: usize,
    pub(super) path_bytes: usize,
}

impl FileDiscoveryBudget {
    fn new(retained_results: usize) -> Self {
        Self {
            retained_results,
            entry_visits: FILE_PICKER_ENTRY_VISIT_LIMIT,
            depth: FILE_PICKER_MAX_DEPTH,
            path_bytes: FILE_PICKER_PATH_BYTE_LIMIT,
        }
    }
}

pub(super) struct FileDiscovery<'a> {
    root: &'a Path,
    budget: FileDiscoveryBudget,
    directories: Vec<(PathBuf, usize)>,
    retained: BinaryHeap<String>,
    limits_reached: BTreeSet<FileCompletionLimit>,
    entries_visited: usize,
    path_bytes_observed: usize,
}

impl<'a> FileDiscovery<'a> {
    pub(super) fn new(root: &'a Path, budget: FileDiscoveryBudget) -> Self {
        Self {
            root,
            budget,
            directories: vec![(root.to_path_buf(), 0)],
            retained: BinaryHeap::new(),
            limits_reached: BTreeSet::new(),
            entries_visited: 0,
            path_bytes_observed: 0,
        }
    }

    pub(super) fn run(mut self, is_canceled: impl Fn() -> bool) -> Option<FileCompletionIndex> {
        while let Some((directory, depth)) = self.directories.pop() {
            match self.visit_directory(&directory, depth, &is_canceled) {
                DirectoryVisit::Continue => {}
                DirectoryVisit::Stop => break,
                DirectoryVisit::Canceled => return None,
            }
        }
        Some(self.finish())
    }

    fn visit_directory(
        &mut self,
        directory: &Path,
        depth: usize,
        is_canceled: &impl Fn() -> bool,
    ) -> DirectoryVisit {
        let Ok(mut entries) = fs::read_dir(directory) else {
            self.limits_reached
                .insert(FileCompletionLimit::UnreadableDirectory);
            return DirectoryVisit::Continue;
        };
        loop {
            if is_canceled() {
                return DirectoryVisit::Canceled;
            }
            match self.visit_directory_chunk(&mut entries, depth) {
                DirectoryChunk::More => {}
                DirectoryChunk::Finished => return DirectoryVisit::Continue,
                DirectoryChunk::BudgetReached => return DirectoryVisit::Stop,
            }
        }
    }

    fn visit_directory_chunk(&mut self, entries: &mut fs::ReadDir, depth: usize) -> DirectoryChunk {
        for _ in 0..FILE_PICKER_DIRECTORY_CHUNK {
            if self.entries_visited >= self.budget.entry_visits {
                self.limits_reached.insert(FileCompletionLimit::EntryVisits);
                return DirectoryChunk::BudgetReached;
            }
            let Some(entry) = entries.next() else {
                return DirectoryChunk::Finished;
            };
            self.entries_visited += 1;
            if self.visit_entry(entry, depth) == EntryVisit::BudgetReached {
                return DirectoryChunk::BudgetReached;
            }
        }
        DirectoryChunk::More
    }

    fn visit_entry(&mut self, entry: std::io::Result<fs::DirEntry>, depth: usize) -> EntryVisit {
        let Ok(entry) = entry else {
            self.mark_unreadable_inventory();
            return EntryVisit::Continue;
        };
        let path = entry.path();
        let Some(relative) = path.strip_prefix(self.root).ok() else {
            return EntryVisit::Continue;
        };
        if !self.observe_path(relative) {
            return EntryVisit::BudgetReached;
        }
        self.classify_entry(entry, &path, relative, depth);
        EntryVisit::Continue
    }

    fn observe_path(&mut self, relative: &Path) -> bool {
        let next = self
            .path_bytes_observed
            .saturating_add(path_byte_len(relative));
        if next > self.budget.path_bytes {
            self.limits_reached.insert(FileCompletionLimit::PathBytes);
            return false;
        }
        self.path_bytes_observed = next;
        true
    }

    fn classify_entry(&mut self, entry: fs::DirEntry, path: &Path, relative: &Path, depth: usize) {
        self.classify_file_type(entry.file_type(), path, relative, depth);
    }

    fn classify_file_type(
        &mut self,
        file_type: std::io::Result<fs::FileType>,
        path: &Path,
        relative: &Path,
        depth: usize,
    ) {
        let Ok(file_type) = file_type else {
            self.mark_unreadable_inventory();
            return;
        };
        if file_type.is_dir() {
            self.retain_directory(path.to_path_buf(), depth + 1);
        } else if file_type.is_file() {
            self.retain_file(relative.to_string_lossy().into_owned());
        }
    }

    fn mark_unreadable_inventory(&mut self) {
        self.limits_reached
            .insert(FileCompletionLimit::UnreadableDirectory);
    }

    fn retain_directory(&mut self, path: PathBuf, depth: usize) {
        if ignored_picker_dir(&path) {
            return;
        }
        if depth > self.budget.depth {
            self.limits_reached.insert(FileCompletionLimit::Depth);
            return;
        }
        self.directories.push((path, depth));
    }

    fn retain_file(&mut self, path: String) {
        if self.retained.len() < self.budget.retained_results {
            self.retained.push(path);
            return;
        }
        self.limits_reached
            .insert(FileCompletionLimit::RetainedResults);
        let Some(mut largest) = self.retained.peek_mut() else {
            return;
        };
        if path < *largest {
            *largest = path;
        }
    }

    fn finish(self) -> FileCompletionIndex {
        let mut values = self.retained.into_vec();
        values.sort();
        FileCompletionIndex {
            values,
            limits_reached: self.limits_reached,
            entries_visited: self.entries_visited,
            path_bytes_observed: self.path_bytes_observed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryVisit {
    Continue,
    Stop,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryChunk {
    More,
    Finished,
    BudgetReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryVisit {
    Continue,
    BudgetReached,
}

#[cfg(unix)]
fn path_byte_len(path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().len()
}

#[cfg(windows)]
fn path_byte_len(path: &Path) -> usize {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().count().saturating_mul(2)
}

#[cfg(not(any(unix, windows)))]
fn path_byte_len(path: &Path) -> usize {
    path.to_string_lossy().len()
}

#[cfg(test)]
pub(super) fn synthetic_file_candidates(
    mut candidates: impl Iterator<Item = String>,
    budget: FileDiscoveryBudget,
) -> FileCompletionIndex {
    let mut discovery = FileDiscovery::new(Path::new("."), budget);
    discovery.directories.clear();
    loop {
        if discovery.entries_visited >= budget.entry_visits {
            discovery
                .limits_reached
                .insert(FileCompletionLimit::EntryVisits);
            break;
        }
        let Some(path) = candidates.next() else {
            break;
        };
        discovery.entries_visited += 1;
        if !discovery.observe_path(Path::new(&path)) {
            break;
        }
        discovery.retain_file(path);
    }
    discovery.finish()
}

fn ignored_picker_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    matches!(
        name,
        ".git" | ".kuzushi" | "node_modules" | "target" | "dist" | "build" | ".next" | "coverage"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_and_file_type_errors_mark_the_index_partial() {
        let budget = FileDiscoveryBudget::new(10);
        let mut discovery = FileDiscovery::new(Path::new("."), budget);
        let error = || std::io::Error::other("fixture read error");

        discovery.visit_entry(Err(error()), 0);
        discovery.classify_file_type(Err(error()), Path::new("file.rs"), Path::new("file.rs"), 0);

        assert!(discovery
            .limits_reached
            .contains(&FileCompletionLimit::UnreadableDirectory));
    }
}
