use super::*;
use crate::workspace::infrastructure::{
    InventoryDirectory, InventoryEntry, InventoryEntryKind, InventoryRoot,
};
use std::io::Read;

pub(crate) const MAX_REPOSITORY_ENTRIES: usize = 100_000;
pub(crate) const MAX_REPOSITORY_INSPECTED_BYTES: usize = 512 * 1024 * 1024;
const MAX_FILE_INSPECTION_BYTES: usize = 256 * 1024;

struct InventoryBudget<'p> {
    entries: usize,
    inspected_bytes: usize,
    max_entries: usize,
    max_inspected_bytes: usize,
    truncation: Option<String>,
    canceled: bool,
    enumeration_incomplete: bool,
    truncated_files: Vec<String>,
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
    build_with_enumeration(
        root,
        max_entries,
        max_inspected_bytes,
        on_entries,
        should_cancel,
        None,
    )
}

pub(crate) fn build_repository_inventory_from_enumeration(
    root: &Path,
    on_entries: &mut dyn FnMut(usize),
    should_cancel: &dyn Fn() -> bool,
    enumeration: crate::workspace::GitIndexEnumeration,
    max_inspected_bytes: usize,
) -> Result<RepositoryInventory> {
    build_with_enumeration(
        root,
        MAX_REPOSITORY_ENTRIES,
        max_inspected_bytes,
        on_entries,
        should_cancel,
        Some(enumeration),
    )
}

fn build_with_enumeration(
    root: &Path,
    max_entries: usize,
    max_inspected_bytes: usize,
    on_entries: &mut dyn FnMut(usize),
    should_cancel: &dyn Fn() -> bool,
    enumeration: Option<crate::workspace::GitIndexEnumeration>,
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
    let reader = InventoryRoot::new(&root)?;
    let enumeration = enumerate_repository(
        &root,
        &reader,
        &mut builder,
        &mut budget,
        should_cancel,
        enumeration,
    )?;
    reader.verify_current_root()?;
    let inspection = budget.receipt(enumeration);
    let truncation = budget
        .truncation
        .map(|reason| InventoryTruncation { reason });
    Ok(builder.finish(root_name(&root), truncation, inspection))
}

fn enumerate_repository(
    root: &Path,
    reader: &InventoryRoot,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
    should_cancel: &dyn Fn() -> bool,
    enumeration: Option<crate::workspace::GitIndexEnumeration>,
) -> Result<&'static str> {
    use crate::workspace::GitIndexEnumeration;
    let enumeration = enumeration.map_or_else(
        || crate::workspace::git_tracked_relative_paths(root, budget.max_entries, should_cancel),
        Ok,
    )?;
    match enumeration {
        GitIndexEnumeration::Tracked { paths, .. } => {
            walk_git_index(root, reader, &paths, builder, budget)?;
            Ok("git-index")
        }
        GitIndexEnumeration::Unavailable => {
            walk_repository(root, reader, root, builder, budget)?;
            Ok("filesystem")
        }
        GitIndexEnumeration::Canceled => {
            budget.canceled = true;
            budget.mark_truncated(
                "canceled by operator during Git path acquisition; no files inspected".into(),
            );
            Ok("interrupted")
        }
    }
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
            enumeration_incomplete: false,
            truncated_files: Vec::new(),
            progress: Some(progress),
            cancel: None,
        }
    }

    fn receipt(&self, enumeration: &str) -> InventoryInspection {
        InventoryInspection {
            enumeration_complete: Some(!self.enumeration_incomplete && !self.canceled),
            files: Vec::new(),
            enumeration: enumeration.into(),
            entries: self.entries,
            inspected_bytes: self.inspected_bytes,
            max_entries: self.max_entries,
            max_inspected_bytes: self.max_inspected_bytes,
            max_file_inspection_bytes: MAX_FILE_INSPECTION_BYTES,
            omitted_paths: Vec::new(),
            truncated_files: self.truncated_files.clone(),
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

    /// Enumerates one directory deterministically: every entry is drained
    /// and sorted by path before the entry cap applies, so a capped walk
    /// covers a lexicographic prefix regardless of filesystem order. A
    /// directory whose drain is canceled admits nothing, because its sorted
    /// prefix is unknown.
    fn collect_dir(
        &mut self,
        read_dir: InventoryDirectory,
        dir: &Path,
    ) -> Result<Vec<InventoryEntry>> {
        let mut entries = self.drain_directory(read_dir, dir)?;
        if self.canceled {
            return Ok(Vec::new());
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(self.admit_sorted_prefix(entries, dir))
    }

    fn drain_directory(
        &mut self,
        read_dir: InventoryDirectory,
        dir: &Path,
    ) -> Result<Vec<InventoryEntry>> {
        let mut entries = Vec::new();
        for entry in read_dir {
            if self.cancel_requested(dir) {
                break;
            }
            entries.push(entry.with_context(|| format!("Could not enumerate {}", dir.display()))?);
        }
        Ok(entries)
    }

    /// Counts the sorted entries that fit under the entry cap and discloses
    /// the truncation when any entry is left out.
    fn admit_sorted_prefix(
        &mut self,
        mut entries: Vec<InventoryEntry>,
        dir: &Path,
    ) -> Vec<InventoryEntry> {
        let room = self.max_entries.saturating_sub(self.entries);
        if entries.len() > room {
            entries.truncate(room);
            self.enumeration_incomplete = true;
            self.mark_truncated(format!(
                "entry cap of {} reached at {}; inventory covers the enumerated prefix only",
                self.max_entries,
                dir.display()
            ));
        }
        entries.iter().for_each(|_| self.count_entry());
        entries
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
    reader: &InventoryRoot,
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
        walk_tracked_file(reader, &path, relative, builder, budget, &mut dispositions)?;
    }
    Ok(())
}

fn mark_enumeration_cap(budget: &mut InventoryBudget<'_>, relative: &str) {
    budget.enumeration_incomplete = true;
    if !budget.canceled {
        budget.mark_truncated(format!(
            "entry cap of {} reached at {relative}; inventory covers the enumerated prefix only",
            budget.max_entries
        ));
    }
}

fn walk_tracked_file(
    reader: &InventoryRoot,
    path: &Path,
    relative: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
    dispositions: &mut BTreeMap<String, DirDisposition>,
) -> Result<()> {
    if dir_disposition(relative, builder, dispositions) != DirDisposition::Walk {
        return Ok(());
    }
    if reader.is_known_non_regular(path) {
        builder.omit_path(relative, "symlinks and non-regular files are not followed");
        return Ok(());
    }
    let name = relative.rsplit('/').next().unwrap_or(relative);
    walk_repository_file(reader, path, relative, name, builder, budget)
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
    let mut parent = String::new();
    let mut disposition = DirDisposition::Walk;
    for segment in dir.split('/') {
        append_directory_segment(&mut parent, segment);
        disposition = cached_dir_disposition(&parent, disposition, builder, dispositions);
    }
    disposition
}

fn append_directory_segment(parent: &mut String, segment: &str) {
    if !parent.is_empty() {
        parent.push('/');
    }
    parent.push_str(segment);
}

fn cached_dir_disposition(
    dir: &str,
    inherited: DirDisposition,
    builder: &mut InventoryBuilder,
    dispositions: &mut BTreeMap<String, DirDisposition>,
) -> DirDisposition {
    dispositions
        .entry(dir.to_string())
        .or_insert_with(|| {
            if inherited == DirDisposition::Walk {
                own_dir_disposition(dir, builder)
            } else {
                inherited
            }
        })
        .clone()
}

fn own_dir_disposition(dir: &str, builder: &mut InventoryBuilder) -> DirDisposition {
    let name = dir.rsplit('/').next().unwrap_or(dir);
    if ignored_dir(name) {
        builder.omit_path(dir, "ignored directory");
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
    reader: &InventoryRoot,
    dir: &Path,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let mut pending = repository_directory_entries(root, reader, dir, builder, budget)?;
    while let Some(entry) = pending.pop() {
        if budget.cancel_requested(&entry.path) {
            break;
        }
        pending.extend(walk_repository_entry(root, reader, entry, builder, budget)?);
    }
    Ok(())
}

/// Entries are reversed for an iterative depth-first walk. No directory walk
/// consumes the Rust call stack, and every discovered entry shares one budget.
fn repository_directory_entries(
    root: &Path,
    reader: &InventoryRoot,
    dir: &Path,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<Vec<InventoryEntry>> {
    if budget.halted(dir) {
        budget.enumeration_incomplete = true;
        if !budget.canceled {
            budget.mark_truncated(format!(
                "entry cap reached before walking {}; inventory covers the walked prefix only",
                dir.display()
            ));
        }
        return Ok(Vec::new());
    }
    let read_dir = match reader.read_directory(dir) {
        Ok(entries) => entries,
        Err(error) => {
            budget.enumeration_incomplete = true;
            builder.omit_path(&repo_relative(root, dir), &format!("directory could not be opened within the repository without following symlinks: {error}"));
            budget.mark_truncated(format!(
                "directory unavailable or unsafe at {}; inventory excludes this boundary",
                repo_relative(root, dir)
            ));
            return Ok(Vec::new());
        }
    };
    let mut entries = budget.collect_dir(read_dir, dir)?;
    entries.reverse();
    Ok(entries)
}

fn walk_repository_entry(
    root: &Path,
    reader: &InventoryRoot,
    entry: InventoryEntry,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<Vec<InventoryEntry>> {
    let path = entry.path;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let relative = repo_relative(root, &path);

    if entry.kind == InventoryEntryKind::Directory {
        return walk_repository_dir(root, reader, &path, &relative, &name, builder, budget);
    }
    if entry.kind == InventoryEntryKind::File {
        walk_repository_file(reader, &path, &relative, &name, builder, budget)?;
    } else {
        builder.omit_path(&relative, "symlinks and non-regular files are not followed");
    }
    Ok(Vec::new())
}

fn walk_repository_dir(
    root: &Path,
    reader: &InventoryRoot,
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<Vec<InventoryEntry>> {
    if ignored_dir(name) {
        builder.omit_path(relative, "ignored directory");
        return Ok(Vec::new());
    }
    if let Some(classification) = generated_vendor_path(relative, name, true) {
        builder.add_generated_vendor_path(classification);
        return Ok(Vec::new());
    }
    repository_directory_entries(root, reader, path, builder, budget)
}

fn walk_repository_file(
    reader: &InventoryRoot,
    path: &Path,
    relative: &str,
    name: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Result<()> {
    let Some(file) = open_inventory_file(reader, path, relative, builder, budget) else {
        return Ok(());
    };
    builder.enumerated_files.insert(relative.to_string());
    let generated_vendor = record_file_metadata(relative, name, builder);
    let Some(inspectable) = approved_inspection_bytes(&file, path, relative, budget)? else {
        return Ok(());
    };
    let Some(text) = crate::bounded_file::read_source_text_prefix_from_reader(
        file.take(inspectable as u64),
        inspectable,
    )
    .with_context(|| format!("Could not inspect repository file {relative}"))?
    else {
        return Ok(());
    };
    inspect_manifest_frameworks(relative, name, &text, builder);
    if generated_vendor.is_some() {
        return Ok(());
    }
    record_source_file(path, relative, &text, builder);
    Ok(())
}

fn open_inventory_file(
    reader: &InventoryRoot,
    path: &Path,
    relative: &str,
    builder: &mut InventoryBuilder,
    budget: &mut InventoryBudget<'_>,
) -> Option<fs::File> {
    match reader.open_file(path) {
        Ok(file) => Some(file),
        Err(error) => {
            budget.enumeration_incomplete = true;
            builder.omit_path(relative, &format!("file could not be opened within the repository without following symlinks: {error}"));
            budget.mark_truncated(format!(
                "file unavailable or unsafe at {relative}; inventory excludes this path"
            ));
            None
        }
    }
}

/// Charges the content-inspection budget BEFORE any disk read, from file
/// metadata: once the byte budget is exhausted the walk performs zero
/// further reads and continues metadata-only.
fn approved_inspection_bytes(
    file: &fs::File,
    path: &Path,
    relative: &str,
    budget: &mut InventoryBudget<'_>,
) -> Result<Option<usize>> {
    let size = file
        .metadata()
        .with_context(|| format!("Could not inspect opened repository file {relative}"))?
        .len() as usize;
    let inspectable = size.min(MAX_FILE_INSPECTION_BYTES);
    if size > MAX_FILE_INSPECTION_BYTES {
        budget.truncated_files.push(relative.into());
        budget.mark_truncated(format!("per-file inspection cap of {MAX_FILE_INSPECTION_BYTES} bytes reached; larger files are inspected as prefixes"));
    }
    Ok(budget
        .record_inspected_bytes(inspectable, path)
        .then_some(inspectable))
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
    fn prefix_inspection_does_not_hide_a_later_enumeration_limit() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("a.c"),
            vec![b' '; MAX_FILE_INSPECTION_BYTES + 1],
        )
        .unwrap();
        fs::write(root.path().join("b.c"), "// inert\n").unwrap();
        fs::write(root.path().join("c.c"), "// inert\n").unwrap();
        let inventory = build_with_enumeration(
            root.path(),
            2,
            MAX_REPOSITORY_INSPECTED_BYTES,
            &mut |_| {},
            &|| false,
            Some(crate::workspace::GitIndexEnumeration::Tracked {
                paths: vec!["a.c".into(), "b.c".into(), "c.c".into()],
                fingerprint: "owned-test-enumeration".into(),
            }),
        )
        .unwrap();
        assert!(inventory
            .truncation
            .unwrap()
            .reason
            .contains("per-file inspection cap"));
        assert_eq!(
            inventory.inspection.unwrap().enumeration_complete,
            Some(false)
        );
    }

    #[test]
    fn complete_enumeration_and_legacy_unknown_are_distinct_from_content_prefixes() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("a.c"),
            vec![b' '; MAX_FILE_INSPECTION_BYTES + 1],
        )
        .unwrap();
        let inventory = build_repository_inventory(root.path()).unwrap();
        assert!(inventory.truncation.is_some());
        let inspection = inventory.inspection.unwrap();
        assert_eq!(inspection.enumeration_complete, Some(true));
        let mut legacy = serde_json::to_value(inspection).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("enumeration_complete");
        assert_eq!(
            serde_json::from_value::<InventoryInspection>(legacy)
                .unwrap()
                .enumeration_complete,
            None
        );
    }

    #[test]
    fn inspection_receipt_discloses_omissions_and_per_file_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join(".kuzushi")).unwrap();
        fs::write(
            temp.path().join(".kuzushi/private.rs"),
            "pub fn hidden() {}",
        )
        .unwrap();
        fs::write(
            temp.path().join("large.rs"),
            vec![b' '; MAX_FILE_INSPECTION_BYTES + 1],
        )
        .unwrap();
        let result = build_repository_inventory(temp.path()).unwrap();
        assert!(result
            .truncation
            .unwrap()
            .reason
            .contains("per-file inspection cap"));
        let receipt = result.inspection.unwrap();
        assert_eq!(receipt.enumeration, "filesystem");
        assert_eq!(receipt.inspected_bytes, MAX_FILE_INSPECTION_BYTES);
        assert_eq!(receipt.truncated_files, vec!["large.rs"]);
        assert!(receipt
            .omitted_paths
            .iter()
            .any(|entry| entry.path == ".kuzushi"));
    }

    fn unsorted_directory(names: &[&str]) -> InventoryDirectory {
        let entries: Vec<_> = names
            .iter()
            .map(|name| {
                Ok(InventoryEntry {
                    path: std::path::PathBuf::from("/repo").join(name),
                    kind: InventoryEntryKind::File,
                })
            })
            .collect();
        Box::new(entries.into_iter())
    }

    fn enumerated_names(entries: &[InventoryEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| entry.path.file_name().unwrap().to_string_lossy().into())
            .collect()
    }

    #[test]
    fn entry_cap_admits_the_sorted_prefix_regardless_of_directory_order() {
        let mut progress = |_| {};
        let mut budget = InventoryBudget::new(2, 1024, &mut progress);
        let entries = budget
            .collect_dir(
                unsorted_directory(&["c.rs", "a.rs", "b.rs"]),
                Path::new("/repo"),
            )
            .unwrap();
        assert_eq!(enumerated_names(&entries), vec!["a.rs", "b.rs"]);
        assert_eq!(budget.entries, 2);
        assert!(budget.enumeration_incomplete);
        assert!(budget
            .truncation
            .unwrap()
            .contains("inventory covers the enumerated prefix only"));
    }

    #[test]
    fn uncapped_directory_is_enumerated_in_sorted_order_without_truncation() {
        let mut progress = |_| {};
        let mut budget = InventoryBudget::new(3, 1024, &mut progress);
        let entries = budget
            .collect_dir(
                unsorted_directory(&["c.rs", "a.rs", "b.rs"]),
                Path::new("/repo"),
            )
            .unwrap();
        assert_eq!(enumerated_names(&entries), vec!["a.rs", "b.rs", "c.rs"]);
        assert!(!budget.enumeration_incomplete);
        assert!(budget.truncation.is_none());
    }

    #[test]
    fn deeply_nested_filesystem_inventory_uses_one_bounded_walk() {
        let temp = tempfile::tempdir().unwrap();
        let mut nested = temp.path().to_path_buf();
        for _ in 0..256 {
            nested.push("d");
            fs::create_dir(&nested).unwrap();
        }
        fs::write(nested.join("leaf.rs"), "pub fn leaf() {}\n").unwrap();
        let result =
            build_repository_inventory_with_limits(temp.path(), 300, 1024, &mut |_| {}, &|| false)
                .unwrap();
        assert_eq!(result.source_files.len(), 1);
        assert!(result.truncation.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_inventory_does_not_follow_cycles_or_external_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("local.rs"), "pub fn local() {}\n").unwrap();
        fs::write(
            external.path().join("external.rs"),
            "pub fn external() {}\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(temp.path(), temp.path().join("cycle")).unwrap();
        std::os::unix::fs::symlink(external.path(), temp.path().join("outside")).unwrap();
        let result = build_repository_inventory(temp.path()).unwrap();
        assert_eq!(result.source_files.len(), 1);
        assert_eq!(result.source_files[0].path, "local.rs");
        assert!(result.truncation.is_none());
    }

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

    #[test]
    fn canceled_acquisition_returns_an_honest_empty_partial() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("untracked.rs"), "// inert fixture\n").unwrap();
        let inventory =
            build_repository_inventory_with_limits(temp.path(), 100, 1024, &mut |_| {}, &|| true)
                .unwrap();
        assert!(inventory.source_files.is_empty());
        assert!(inventory
            .truncation
            .unwrap()
            .reason
            .contains("during Git path acquisition"));
        let receipt = inventory.inspection.unwrap();
        assert_eq!(receipt.enumeration, "interrupted");
        assert_eq!(receipt.entries, 0);
        assert_eq!(receipt.inspected_bytes, 0);
    }

    #[test]
    fn capped_git_acquisition_keeps_overflow_visible_to_the_receipt() {
        let temp = tempfile::tempdir().unwrap();
        for name in ["a.rs", "b.rs", "c.rs"] {
            fs::write(temp.path().join(name), "// inert fixture\n").unwrap();
        }
        seed_git_worktree(temp.path());
        let inventory =
            build_repository_inventory_with_limits(temp.path(), 2, 1024, &mut |_| {}, &|| false)
                .unwrap();
        assert_eq!(inventory.source_files.len(), 2);
        assert!(inventory.truncation.unwrap().reason.contains("entry cap"));
        assert_eq!(inventory.inspection.unwrap().enumeration, "git-index");
    }

    #[cfg(unix)]
    #[test]
    fn git_index_inventory_reports_unsafe_ancestors_without_reading_their_files() {
        let temp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir(root.join("component")).unwrap();
        fs::write(root.join("component/source.rs"), "fn owned() {}\n").unwrap();
        fs::write(root.join("owned.rs"), "fn owned() {}\n").unwrap();
        seed_git_index(root);
        fs::rename(root.join("component"), root.join("original-component")).unwrap();
        fs::write(external.path().join("source.rs"), "fn excluded() {}\n").unwrap();
        std::os::unix::fs::symlink(external.path(), root.join("component")).unwrap();

        let inventory = build_repository_inventory(root).unwrap();
        assert_eq!(inventory.source_files.len(), 1);
        assert_eq!(inventory.source_files[0].path, "owned.rs");
        assert!(inventory.truncation.is_some());
        let inspection = inventory.inspection.unwrap();
        assert_eq!(inspection.files, vec!["owned.rs"]);
        assert!(inspection
            .omitted_paths
            .iter()
            .any(|entry| entry.path == "component/source.rs"));
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
        assert!(
            inventory.truncation.is_none(),
            "Known symlink exclusion is not incomplete enumeration"
        );
        let inspection = inventory.inspection.unwrap();
        assert_eq!(inspection.enumeration_complete, Some(true));
        assert_eq!(inspection.files, vec!["real.rs"]);
        assert!(inspection
            .omitted_paths
            .iter()
            .any(|entry| entry.path == "alias.rs"));
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

    #[test]
    fn cancellation_interrupts_wide_directory_collection_before_the_entry_cap() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        for i in 0..200 {
            fs::write(temp.path().join(format!("source-{i}.rs")), "// owned\n").unwrap();
        }
        let probes = std::cell::Cell::new(0);
        let cancel = || {
            probes.set(probes.get() + 1);
            probes.get() > 5
        };
        let mut progress = |_| {};
        let mut budget = InventoryBudget::new(1000, 1024, &mut progress);
        budget.cancel = Some(&cancel);
        let reader = InventoryRoot::new(temp.path()).unwrap();
        let entries = budget
            .collect_dir(reader.read_directory(temp.path()).unwrap(), temp.path())
            .unwrap();
        assert_eq!(probes.get(), 6, "cancellation lands within one entry");
        assert!(entries.is_empty(), "an undrained directory has no sorted prefix");
        assert_eq!(budget.entries, 0);
        assert!(budget.canceled);
        assert!(budget
            .truncation
            .as_ref()
            .unwrap()
            .contains("canceled by operator"));
    }

    #[cfg(unix)]
    #[test]
    fn directory_replacement_during_progress_does_not_enumerate_external_names() {
        let temp = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let external = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let boundary = temp.path().join("service");
        fs::create_dir(&boundary).unwrap();
        fs::write(boundary.join("initial.rs"), "// initial owned source\n").unwrap();
        fs::write(temp.path().join("owned.rs"), "// owned source\n").unwrap();
        fs::write(external.path().join("excluded.rs"), "// excluded source\n").unwrap();
        let mut replaced = false;
        let mut progress = |_| {
            if !replaced {
                fs::rename(&boundary, temp.path().join("original-service")).unwrap();
                std::os::unix::fs::symlink(external.path(), &boundary).unwrap();
                replaced = true;
            }
        };
        let mut budget = InventoryBudget::new(100, 1024, &mut progress);
        let mut builder = InventoryBuilder::default();
        let reader = InventoryRoot::new(temp.path()).unwrap();
        walk_repository(temp.path(), &reader, temp.path(), &mut builder, &mut budget).unwrap();
        let inspection = budget.receipt("filesystem");
        let result = builder.finish(
            "owned".into(),
            budget
                .truncation
                .map(|reason| InventoryTruncation { reason }),
            inspection,
        );
        assert!(!result
            .inspection
            .as_ref()
            .unwrap()
            .files
            .iter()
            .any(|path| path.contains("excluded")));
        assert!(result
            .source_files
            .iter()
            .any(|file| file.path == "owned.rs"));
        assert!(result.truncation.is_some());
    }

    fn seed_git_index(root: &Path) {
        for args in [vec!["init", "-q"], vec!["add", "-A"]] {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[cfg(unix)]
    #[test]
    fn metadata_only_inventory_excludes_unsafe_members_before_charging_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("component")).unwrap();
        fs::write(temp.path().join("component/source.rs"), "fn initial() {}\n").unwrap();
        fs::write(temp.path().join("owned.rs"), "fn owned() {}\n").unwrap();
        seed_git_index(temp.path());
        fs::remove_dir_all(temp.path().join("component")).unwrap();
        fs::write(external.path().join("source.rs"), "fn excluded() {}\n").unwrap();
        std::os::unix::fs::symlink(external.path(), temp.path().join("component")).unwrap();
        let result =
            build_repository_inventory_with_limits(temp.path(), 100, 0, &mut |_| {}, &|| false)
                .unwrap();
        let inspection = result.inspection.unwrap();
        assert_eq!(inspection.files, vec!["owned.rs"]);
        assert_eq!(inspection.inspected_bytes, 0);
        assert!(inspection
            .omitted_paths
            .iter()
            .any(|row| row.path == "component/source.rs"));
        assert!(result.truncation.is_some());
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
