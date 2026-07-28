use super::*;

const MAX_REPOSITORY_ENTRIES: usize = 100_000;
pub(crate) const MAX_REPOSITORY_INSPECTED_BYTES: usize = 512 * 1024 * 1024;
const MAX_FILE_INSPECTION_BYTES: usize = 256 * 1024;

struct InventoryBudget<'p> {
    entries: usize,
    inspected_bytes: usize,
    max_entries: usize,
    max_inspected_bytes: usize,
    truncation: Option<String>,
    canceled: bool,
    /// Walked-entry observer: monorepo walks run for minutes, and a silent
    /// walk reads as a hung run — callers surface these counts as heartbeat
    /// progress.
    progress: Option<&'p mut dyn FnMut(usize)>,
    /// Cooperative cancellation probe checked once per entry so an operator
    /// abort lands within one file, never after the whole walk.
    cancel: Option<&'p dyn Fn() -> bool>,
}

pub fn build_repository_inventory(root: impl AsRef<Path>) -> Result<RepositoryInventory> {
    build_repository_inventory_with_progress(root, |_| {})
}

pub fn build_repository_inventory_with_progress(
    root: impl AsRef<Path>,
    mut on_entries: impl FnMut(usize),
) -> Result<RepositoryInventory> {
    build_repository_inventory_with_observer(root, &mut on_entries, &|| false)
}

/// Full-control walk: heartbeat progress plus a cooperative cancellation
/// probe. A canceled walk returns the partial inventory it built, marked
/// truncated with a cancellation reason — callers persist it as an honest
/// partial rather than discarding the work.
pub fn build_repository_inventory_with_observer(
    root: impl AsRef<Path>,
    on_entries: &mut dyn FnMut(usize),
    should_cancel: &dyn Fn() -> bool,
) -> Result<RepositoryInventory> {
    build_repository_inventory_with_limits(
        root.as_ref(),
        MAX_REPOSITORY_ENTRIES,
        MAX_REPOSITORY_INSPECTED_BYTES,
        on_entries,
        should_cancel,
    )
}

pub(crate) fn build_repository_inventory_with_limits(
    root: &Path,
    max_entries: usize,
    max_inspected_bytes: usize,
    on_entries: &mut dyn FnMut(usize),
    should_cancel: &dyn Fn() -> bool,
) -> Result<RepositoryInventory> {
    let root = root
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = InventoryBuilder::default();
    let mut budget = InventoryBudget::new(max_entries, max_inspected_bytes, on_entries);
    budget.cancel = Some(should_cancel);
    if let Some(tracked) = crate::workspace::git_tracked_relative_paths(&root) {
        walk_git_index(&root, &tracked, &mut builder, &mut budget)?;
    } else {
        walk_repository(&root, &root, &mut builder, &mut budget)?;
    }
    let truncation = budget
        .truncation
        .map(|reason| InventoryTruncation { reason });
    Ok(builder.finish(root_name(&root), truncation))
}

impl<'p> InventoryBudget<'p> {
    fn new(
        max_entries: usize,
        max_inspected_bytes: usize,
        progress: &'p mut dyn FnMut(usize),
    ) -> Self {
        Self {
            entries: 0,
            inspected_bytes: 0,
            max_entries,
            max_inspected_bytes,
            truncation: None,
            canceled: false,
            progress: Some(progress),
            cancel: None,
        }
    }

    fn entries_exhausted(&self) -> bool {
        self.entries >= self.max_entries
    }

    /// Cooperative cancellation, checked once per entry so an abort lands
    /// within one file. A canceled walk keeps its partial inventory and is
    /// marked truncated with the cancellation point.
    fn cancel_requested(&mut self, at: &Path) -> bool {
        if self.canceled {
            return true;
        }
        if self.cancel.is_some_and(|probe| probe()) {
            self.canceled = true;
            self.mark_truncated(format!(
                "canceled by operator after {} entries at {}; inventory is a partial prefix",
                self.entries,
                at.display()
            ));
            return true;
        }
        false
    }

    /// True once the walk must stop adding entries: cancellation or cap.
    fn halted(&mut self, at: &Path) -> bool {
        self.cancel_requested(at) || self.entries_exhausted()
    }

    fn count_entry(&mut self) {
        self.entries += 1;
        if let Some(progress) = self.progress.as_deref_mut() {
            progress(self.entries);
        }
    }

    fn collect_dir(&mut self, read_dir: fs::ReadDir, dir: &Path) -> Result<Vec<fs::DirEntry>> {
        let remaining = self.max_entries.saturating_sub(self.entries);
        let mut entries = read_dir
            .take(remaining.saturating_add(1))
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("Could not enumerate {}", dir.display()))?;
        if entries.len() > remaining {
            entries.truncate(remaining);
            self.mark_truncated(format!(
                "entry cap of {} reached at {}; inventory covers the walked prefix only",
                self.max_entries,
                dir.display()
            ));
        }
        self.entries += entries.len();
        if let Some(progress) = self.progress.as_deref_mut() {
            progress(self.entries);
        }
        Ok(entries)
    }

    /// Returns whether the file's content may still be inspected. Once the
    /// byte budget is exhausted the walk continues metadata-only.
    fn record_inspected_bytes(&mut self, bytes: usize, path: &Path) -> bool {
        let next = self.inspected_bytes.saturating_add(bytes);
        if next > self.max_inspected_bytes {
            self.mark_truncated(format!(
                "content-inspection cap of {} bytes reached at {}; remaining files recorded metadata-only",
                self.max_inspected_bytes,
                path.display()
            ));
            return false;
        }
        self.inspected_bytes = next;
        true
    }

    fn mark_truncated(&mut self, reason: String) {
        if self.truncation.is_none() {
            self.truncation = Some(reason);
        }
    }
}

/// Directory dispositions mirrored from the fs walk so both enumerations
/// classify identically: ignored dirs are skipped silently, generated/vendor
/// dirs are recorded once and not descended into.
#[derive(Clone, PartialEq, Eq)]
enum DirDisposition {
    Walk,
    SkipIgnored,
    SkipVendor,
}

fn walk_git_index(
    root: &Path,
    tracked: &[String],
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let mut dispositions: BTreeMap<String, DirDisposition> = BTreeMap::new();
    for relative in tracked {
        let path = root.join(relative);
        if budget.halted(&path) {
            mark_enumeration_cap(budget, relative);
            return Ok(());
        }
        budget.count_entry();
        walk_tracked_file(&path, relative, builder, budget, &mut dispositions)?;
    }
    Ok(())
}

fn mark_enumeration_cap(budget: &mut InventoryBudget<'_>, relative: &str) {
    if !budget.canceled {
        budget.mark_truncated(format!(
            "entry cap of {} reached at {relative}; inventory covers the enumerated prefix only",
            budget.max_entries
        ));
    }
}

fn walk_tracked_file(
    path: &Path,
    relative: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
    dispositions: &mut BTreeMap<String, DirDisposition>,
) -> Result<()> {
    if dir_disposition(relative, builder, dispositions) != DirDisposition::Walk {
        return Ok(());
    }
    if !regular_tracked_file(path) {
        return Ok(());
    }
    let name = relative.rsplit('/').next().unwrap_or(relative);
    walk_repository_file(path, relative, name, builder, budget)
}

/// Tracked entries that are not regular files on disk — symlinks (the file
/// reader refuses to follow them) or paths deleted since the index was
/// written — are counted but not read, matching the fs walk's dirent gate.
fn regular_tracked_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// Resolves whether any ancestor directory of the tracked file `relative`
/// is ignored or classified generated/vendor, matching the fs walk's
/// pruning. Root-level files always walk.
fn dir_disposition(
    relative: &str,
    builder: &mut InventoryBuilder,
    dispositions: &mut BTreeMap<String, DirDisposition>,
) -> DirDisposition {
    match relative.rsplit_once('/') {
        Some((parent, _file)) => dir_disposition_for(parent, builder, dispositions),
        None => DirDisposition::Walk,
    }
}

/// Memoized per-directory disposition: a directory inherits any skip from
/// its parent, then applies its own ignored/vendor classification.
fn dir_disposition_for(
    dir: &str,
    builder: &mut InventoryBuilder,
    dispositions: &mut BTreeMap<String, DirDisposition>,
) -> DirDisposition {
    if let Some(known) = dispositions.get(dir) {
        return known.clone();
    }
    let inherited = dir_disposition(dir, builder, dispositions);
    let computed = if inherited != DirDisposition::Walk {
        inherited
    } else {
        own_dir_disposition(dir, builder)
    };
    dispositions.insert(dir.to_string(), computed.clone());
    computed
}

fn own_dir_disposition(dir: &str, builder: &mut InventoryBuilder) -> DirDisposition {
    let name = dir.rsplit('/').next().unwrap_or(dir);
    if ignored_dir(name) {
        return DirDisposition::SkipIgnored;
    }
    if let Some(classification) = generated_vendor_path(dir, name, true) {
        builder.add_generated_vendor_path(classification);
        return DirDisposition::SkipVendor;
    }
    DirDisposition::Walk
}

fn walk_repository(
    root: &Path,
    dir: &Path,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    if budget.halted(dir) {
        if !budget.canceled {
            budget.mark_truncated(format!(
                "entry cap reached before walking {}; inventory covers the walked prefix only",
                dir.display()
            ));
        }
        return Ok(());
    }
    let read_dir = fs::read_dir(dir)
        .with_context(|| format!("Could not read repository directory {}", dir.display()))?;
    let mut entries = budget.collect_dir(read_dir, dir)?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        if budget.cancel_requested(&entry.path()) {
            return Ok(());
        }
        walk_repository_entry(root, entry, builder, budget)?;
    }

    Ok(())
}

fn walk_repository_entry(
    root: &Path,
    entry: fs::DirEntry,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let path = entry.path();
    let file_type = entry
        .file_type()
        .with_context(|| format!("Could not inspect repository entry {}", path.display()))?;
    let name = entry.file_name().to_string_lossy().to_string();
    let relative = repo_relative(root, &path);

    if file_type.is_dir() {
        return walk_repository_dir(root, &path, &relative, &name, builder, budget);
    }
    if file_type.is_file() {
        walk_repository_file(&path, &relative, &name, builder, budget)?;
    }
    Ok(())
}

fn walk_repository_dir(
    root: &Path,
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    if ignored_dir(name) {
        return Ok(());
    }
    if let Some(classification) = generated_vendor_path(relative, name, true) {
        builder.add_generated_vendor_path(classification);
        return Ok(());
    }
    walk_repository(root, path, builder, budget)
}

fn walk_repository_file(
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let generated_vendor = record_file_metadata(relative, name, builder);
    let Some(inspectable) = approved_inspection_bytes(path, budget) else {
        return Ok(());
    };
    let Some(text) = read_text_prefix(path, inspectable)? else {
        return Ok(());
    };
    inspect_manifest_frameworks(relative, name, &text, builder);
    if generated_vendor.is_some() {
        return Ok(());
    }
    record_source_file(path, relative, &text, builder);
    Ok(())
}

/// Charges the content-inspection budget BEFORE any disk read, from file
/// metadata: once the byte budget is exhausted the walk performs zero
/// further reads and continues metadata-only.
fn approved_inspection_bytes(path: &Path, budget: &mut InventoryBudget<'_>) -> Option<usize> {
    let size = fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) as usize;
    let inspectable = size.min(MAX_FILE_INSPECTION_BYTES);
    budget
        .record_inspected_bytes(inspectable, path)
        .then_some(inspectable)
}

fn record_file_metadata(
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
) -> Option<InventoryPathClassification> {
    let generated_vendor = generated_vendor_path(relative, name, false);
    if let Some(classification) = generated_vendor.clone() {
        builder.add_generated_vendor_path(classification);
    }
    if let Some(kind) = manifest_kind(relative, name) {
        builder.add_manifest(relative, kind);
    }
    if let Some(kind) = dependency_manifest_kind(relative, name) {
        builder.add_dependency_manifest(relative, kind);
    }
    if let Some(kind) = config_file_kind(relative, name) {
        builder.add_config_file(relative, kind);
    }
    generated_vendor
}

fn record_source_file(path: &Path, relative: &str, text: &str, builder: &mut InventoryBuilder) {
    let Some(language) = language_for_path(path) else {
        return;
    };
    builder.add_source_file(relative, language, text.len() as u64);
    inspect_source_file(relative, language, text, builder);
}

#[cfg(test)]
mod coverage_limit_tests {
    use super::*;

    #[test]
    fn entry_capped_walk_returns_partial_inventory_marked_truncated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();

        let inventory =
            build_repository_inventory_with_limits(temp.path(), 1, 1024, &mut |_| {}, &|| false)
                .unwrap();

        let truncation = inventory.truncation.expect("partial walk must be marked");
        assert!(truncation.reason.contains("entry cap"));
        assert_eq!(inventory.source_files.len(), 1);
    }

    #[test]
    fn byte_capped_walk_keeps_metadata_and_marks_truncated() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("large.rs"), "x".repeat(64)).unwrap();

        let inventory =
            build_repository_inventory_with_limits(temp.path(), 10, 8, &mut |_| {}, &|| false)
                .unwrap();

        let truncation = inventory
            .truncation
            .expect("partial inspection must be marked");
        assert!(truncation.reason.contains("content-inspection cap"));
        assert!(inventory.source_files.is_empty());
    }

    #[test]
    fn non_git_root_falls_back_to_the_filesystem_walk() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nfunc main() {}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert!(
            inventory
                .source_files
                .iter()
                .any(|file| file.path == "svc/main.go"),
            "a non-git root must be inventoried by the fs walk, never left silently empty"
        );
        assert!(inventory.truncation.is_none());
    }

    #[test]
    fn uncapped_walk_carries_no_truncation_marker() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();

        let inventory =
            build_repository_inventory_with_limits(temp.path(), 100, 1024, &mut |_| {}, &|| false)
                .unwrap();

        assert!(inventory.truncation.is_none());
        assert_eq!(inventory.source_files.len(), 1);
    }

    #[test]
    fn canceled_walk_keeps_partial_inventory_marked_with_cancellation_point() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("a.rs"), "fn a() {}\n").unwrap();
        fs::write(temp.path().join("b.rs"), "fn b() {}\n").unwrap();
        let calls = std::cell::Cell::new(0usize);
        let cancel_after_first = || {
            calls.set(calls.get() + 1);
            calls.get() > 1
        };

        let inventory = build_repository_inventory_with_limits(
            temp.path(),
            100,
            1024,
            &mut |_| {},
            &cancel_after_first,
        )
        .unwrap();

        let truncation = inventory
            .truncation
            .expect("cancellation must be disclosed");
        assert!(truncation.reason.contains("canceled by operator"));
        assert!(inventory.source_files.len() < 2);
    }

    #[cfg(unix)]
    #[test]
    fn git_index_enumeration_skips_tracked_symlinks_instead_of_failing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("real.rs"), "fn real() {}\n").unwrap();
        std::os::unix::fs::symlink(root.join("real.rs"), root.join("alias.rs")).unwrap();
        seed_git_worktree(root);

        let inventory = build_repository_inventory(root).unwrap();

        assert!(inventory
            .source_files
            .iter()
            .any(|file| file.path == "real.rs"));
        assert!(
            !inventory
                .source_files
                .iter()
                .any(|file| file.path == "alias.rs"),
            "tracked symlinks are skipped, matching the fs walk's dirent gate"
        );
    }

    #[test]
    fn git_index_enumeration_matches_fs_walk_on_a_real_worktree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("svc")).unwrap();
        fs::create_dir_all(root.join("vendor/dep")).unwrap();
        fs::write(root.join("svc/main.go"), "package main\nfunc main() {}\n").unwrap();
        fs::write(root.join("vendor/dep/lib.go"), "package dep\n").unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"t\"\n").unwrap();
        seed_git_worktree(root);

        let inventory = build_repository_inventory(root).unwrap();

        assert!(inventory
            .source_files
            .iter()
            .any(|file| file.path == "svc/main.go"));
        assert!(
            !inventory
                .source_files
                .iter()
                .any(|file| file.path.starts_with("vendor/")),
            "vendor files must be classified, not inventoried as source"
        );
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|classification| classification.path == "vendor"));
        assert!(inventory.truncation.is_none());
    }

    fn seed_git_worktree(root: &Path) {
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-qm", "seed"]);
    }
}
