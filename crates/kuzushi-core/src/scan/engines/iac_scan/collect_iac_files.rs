use super::*;
use std::fs::DirEntry;
use std::io;

pub(super) const MAX_IAC_DEPTH: usize = 64;

pub(super) fn collect_iac_files_bounded(
    root: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
    files: &mut Vec<PathBuf>,
    gaps: &mut CoverageGaps,
    inspection: &mut IacInspection,
) -> Result<()> {
    IacWalk {
        root,
        options,
        cancellation,
        files,
        gaps,
        inspection,
    }
    .run(root)
}

struct IacWalk<'a> {
    root: &'a Path,
    options: &'a IacScanOptions,
    cancellation: &'a ScanCancellation,
    files: &'a mut Vec<PathBuf>,
    gaps: &'a mut CoverageGaps,
    inspection: &'a mut IacInspection,
}

impl IacWalk<'_> {
    fn run(&mut self, start: &Path) -> Result<()> {
        let mut pending = vec![(start.to_path_buf(), 0)];
        while let Some((directory, depth)) = pending.pop() {
            self.ensure_active()?;
            if !self.directory(&directory, depth, &mut pending) {
                break;
            }
        }
        self.ensure_active()
    }

    fn ensure_active(&self) -> Result<()> {
        anyhow::ensure!(!self.cancellation.is_cancelled(), "iac-scan scan cancelled");
        Ok(())
    }

    fn directory(
        &mut self,
        directory: &Path,
        depth: usize,
        pending: &mut Vec<(PathBuf, usize)>,
    ) -> bool {
        if depth > MAX_IAC_DEPTH {
            self.gap(
                directory,
                CoverageGapKind::Directory,
                "IaC directory depth limit reached",
            );
            return true;
        }
        match crate::bounded_file::read_dir_within(self.root, directory) {
            Ok(entries) => self.entries(directory, depth, entries, pending),
            Err(error) => {
                self.gaps
                    .record(self.root, directory, CoverageGapKind::Directory, &error);
                true
            }
        }
    }

    fn entries(
        &mut self,
        directory: &Path,
        depth: usize,
        entries: std::fs::ReadDir,
        pending: &mut Vec<(PathBuf, usize)>,
    ) -> bool {
        for entry in entries {
            if self.inspection.entries_visited >= self.options.max_entries {
                self.gap(
                    directory,
                    CoverageGapKind::Directory,
                    "IaC directory entry allowance exhausted; unvisited material remains",
                );
                return false;
            }
            self.inspection.entries_visited += 1;
            if self.cancellation.is_cancelled() {
                return false;
            }
            self.entry(entry, directory, depth, pending);
        }
        true
    }

    fn entry(
        &mut self,
        entry: io::Result<DirEntry>,
        directory: &Path,
        depth: usize,
        pending: &mut Vec<(PathBuf, usize)>,
    ) {
        match entry {
            Ok(entry) => self.classify(&entry, depth, pending),
            Err(error) => self
                .gaps
                .record(self.root, directory, CoverageGapKind::Entry, &error),
        }
    }

    fn classify(&mut self, entry: &DirEntry, depth: usize, pending: &mut Vec<(PathBuf, usize)>) {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) => self.route(&path, kind, depth, pending),
            Err(error) => self
                .gaps
                .record(self.root, &path, CoverageGapKind::Entry, &error),
        }
    }

    fn route(
        &mut self,
        path: &Path,
        kind: std::fs::FileType,
        depth: usize,
        pending: &mut Vec<(PathBuf, usize)>,
    ) {
        if kind.is_symlink() {
            self.inspection.symlinks_excluded += 1;
            return;
        }
        if kind.is_dir() {
            self.directory_entry(path, depth, pending);
            return;
        }
        if kind.is_file()
            && classify_iac_file(self.root, path)
                .is_some_and(|kind| self.options.kind.includes(kind))
        {
            self.files.push(path.to_path_buf());
        }
    }

    fn directory_entry(&mut self, path: &Path, depth: usize, pending: &mut Vec<(PathBuf, usize)>) {
        if should_skip_dir(&path.file_name().unwrap().to_string_lossy()) {
            self.inspection.directories_excluded += 1;
        } else {
            pending.push((path.to_path_buf(), depth + 1));
        }
    }

    fn gap(&mut self, path: &Path, kind: CoverageGapKind, message: &str) {
        self.gaps
            .record(self.root, path, kind, &io::Error::other(message));
    }
}

#[cfg(test)]
pub(crate) fn collect_iac_files(
    root: &Path,
    dir: &Path,
    options: &IacScanOptions,
    files: &mut Vec<PathBuf>,
    gaps: &mut CoverageGaps,
) -> Result<()> {
    IacWalk {
        root,
        options,
        cancellation: &ScanCancellation::default(),
        files,
        gaps,
        inspection: &mut IacInspection::default(),
    }
    .run(dir)
}

pub(crate) fn classify_iac_file(root: &Path, path: &Path) -> Option<IacScanKind> {
    let file_name = path.file_name()?.to_string_lossy();
    if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
        return Some(IacScanKind::Dockerfile);
    }

    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut components = rel.components().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(name.to_string_lossy().to_string()),
        _ => None,
    });
    if components.next().as_deref() == Some(".github")
        && components.next().as_deref() == Some("workflows")
        && matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        )
    {
        return Some(IacScanKind::GithubActions);
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("tf") {
        return Some(IacScanKind::Terraform);
    }

    None
}
