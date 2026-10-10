//! Iterative pack and target walks share the inspection allowance.
use super::LintResources;
use std::{
    collections::BTreeSet,
    fs::ReadDir,
    io,
    path::{Path, PathBuf},
};

impl LintResources<'_> {
    pub(in crate::capabilities::pack_lint) fn walk(
        &self,
        root: &Path,
        start: &Path,
        file_limit: usize,
        recursive: bool,
        skip_hidden: bool,
    ) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if file_limit == 0 {
            self.omit("file-count limit reached; count is a lower bound");
            return files;
        }
        let mut directories = Vec::new();
        let mut visited = BTreeSet::new();
        if let Err(error) = self
            .entry()
            .and_then(|_| self.visit(root, start, &mut files, &mut directories, &mut visited))
        {
            self.omit(format!("{}: {error}", start.display()));
            return files;
        }
        self.walk_entries(
            root,
            &mut files,
            &mut directories,
            &mut visited,
            file_limit,
            recursive,
            skip_hidden,
        );
        files.sort();
        files
    }
    fn walk_entries(
        &self,
        root: &Path,
        files: &mut Vec<PathBuf>,
        directories: &mut Vec<ReadDir>,
        visited: &mut BTreeSet<PathBuf>,
        file_limit: usize,
        recursive: bool,
        skip_hidden: bool,
    ) {
        while let Some(entries) = directories.last_mut() {
            let Some(entry) = entries.next() else {
                directories.pop();
                continue;
            };
            if files.len() >= file_limit {
                self.omit("file-count limit reached; count is a lower bound");
                break;
            }
            if let Err(error) = self.entry() {
                self.omit(error.to_string());
                break;
            }
            self.walk_entry(
                root,
                entry,
                files,
                directories,
                visited,
                recursive,
                skip_hidden,
            );
        }
    }
    fn walk_entry(
        &self,
        root: &Path,
        entry: io::Result<std::fs::DirEntry>,
        files: &mut Vec<PathBuf>,
        directories: &mut Vec<ReadDir>,
        visited: &mut BTreeSet<PathBuf>,
        recursive: bool,
        skip_hidden: bool,
    ) {
        let result = entry.and_then(|entry| {
            if skip_hidden && entry.file_name().to_string_lossy().starts_with('.') {
                self.usage.borrow_mut().hidden += 1;
                return Ok(());
            }
            if !recursive && entry.file_type()?.is_dir() {
                return Ok(());
            }
            self.visit(root, &entry.path(), files, directories, visited)
        });
        if let Err(error) = result {
            self.omit(error.to_string());
        }
    }
    fn visit(
        &self,
        root: &Path,
        path: &Path,
        files: &mut Vec<PathBuf>,
        directories: &mut Vec<ReadDir>,
        visited: &mut BTreeSet<PathBuf>,
    ) -> io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_file() {
            crate::bounded_file::open_regular_file_within(root, path)?;
            files.push(path.to_path_buf());
            return Ok(());
        }
        if !metadata.is_dir() {
            return Err(io::Error::other("symlink or non-regular entry excluded"));
        }
        if !visited.insert(path.to_path_buf()) {
            return Err(io::Error::other("visited directory excluded"));
        }
        directories.push(crate::bounded_file::read_dir_within(root, path)?);
        Ok(())
    }
}

#[cfg(test)]
#[path = "walk/tests.rs"]
mod tests;
