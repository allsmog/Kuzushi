use super::*;
use crate::capabilities::agentic_sast::AgenticInventoryCoverage;

pub(crate) const MAX_AGENTIC_INVENTORY_ENTRIES: usize = 100_000;

pub(crate) struct AgenticInventory {
    pub(crate) snippets: Vec<(String, String)>,
    pub(crate) coverage: AgenticInventoryCoverage,
}

struct InventoryWalk<'a> {
    root: &'a Path,
    options: &'a AgenticSastInput,
    limit: usize,
    probe: &'a dyn Fn() -> Result<()>,
    progress: &'a mut dyn FnMut(usize),
    result: AgenticInventory,
}

pub(crate) fn collect_bounded_inventory(
    root: &Path,
    options: &AgenticSastInput,
    limit: usize,
    probe: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(usize),
) -> Result<AgenticInventory> {
    let mut walk = InventoryWalk::new(root, options, limit, probe, progress);
    let mut pending = walk.directory_entries(root)?;
    while let Some(entry) = pending.pop() {
        probe()?;
        if walk.full() {
            walk.result.coverage.truncation.get_or_insert_with(|| {
                "snippet file limit reached; remaining preparation is uninspected".into()
            });
            break;
        }
        pending.extend(walk.visit(entry)?);
    }
    Ok(walk.result)
}

impl<'a> InventoryWalk<'a> {
    fn new(
        root: &'a Path,
        options: &'a AgenticSastInput,
        limit: usize,
        probe: &'a dyn Fn() -> Result<()>,
        progress: &'a mut dyn FnMut(usize),
    ) -> Self {
        Self {
            root,
            options,
            limit,
            probe,
            progress,
            result: AgenticInventory {
                snippets: Vec::new(),
                coverage: AgenticInventoryCoverage {
                    enumerated_entries: 0,
                    selected_files: 0,
                    ignored_entries: 0,
                    skipped_entries: 0,
                    max_entries: limit,
                    max_files: options.max_inventory_files,
                    max_file_read_bytes: options
                        .max_bytes_per_file
                        .max(crate::bounded_file::BINARY_SNIFF_BYTES)
                        + 1,
                    max_snippet_bytes: options.max_bytes_per_file,
                    snippet_bytes: 0,
                    entry_limit_reached: false,
                    read_limit_reached: false,
                    max_read_bytes: crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES,
                    reserved_read_bytes: 0,
                    truncation: None,
                },
            },
        }
    }

    fn full(&self) -> bool {
        self.result.snippets.len() >= self.options.max_inventory_files
            || self.result.coverage.read_limit_reached
    }

    fn directory_entries(&mut self, path: &Path) -> Result<Vec<fs::DirEntry>> {
        (self.probe)()?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).with_context(|| {
            format!(
                "Could not enumerate source preparation at {}",
                path.display()
            )
        })? {
            (self.probe)()?;
            if self.result.coverage.enumerated_entries >= self.limit {
                self.result.coverage.entry_limit_reached = true;
                self.result.coverage.truncation.get_or_insert_with(|| {
                    "entry limit reached; remaining preparation is uninspected".into()
                });
                break;
            }
            entries.push(entry.context("Could not read a source preparation entry")?);
            self.result.coverage.enumerated_entries += 1;
            (self.progress)(self.result.coverage.enumerated_entries);
        }
        entries.sort_by_key(|entry| entry.path());
        entries.reverse();
        Ok(entries)
    }

    fn visit(&mut self, entry: fs::DirEntry) -> Result<Vec<fs::DirEntry>> {
        if should_skip_path(&entry.file_name().to_string_lossy()) {
            self.result.coverage.ignored_entries += 1;
            return Ok(Vec::new());
        }
        let path = entry.path();
        let kind = entry
            .file_type()
            .context("Could not inspect a source preparation entry")?;
        if kind.is_dir() {
            return self.directory_entries(&path);
        }
        self.add_file(&path, kind.is_file());
        Ok(Vec::new())
    }

    fn add_file(&mut self, path: &Path, regular: bool) {
        if !self.reserve_candidate_read(path, regular) {
            self.result.coverage.skipped_entries += 1;
            return;
        }
        let item = agentic_inventory_file(
            self.root,
            path,
            regular,
            self.options.max_bytes_per_file,
            &self.options.include_patterns,
            &self.options.exclude_patterns,
        );
        match item {
            Some(item) => {
                self.result.coverage.snippet_bytes += item.1.len();
                self.result.coverage.selected_files += 1;
                self.result.snippets.push(item);
            }
            None => self.result.coverage.skipped_entries += 1,
        }
    }
    fn reserve_candidate_read(&mut self, path: &Path, regular: bool) -> bool {
        if agentic_inventory_candidate(
            self.root,
            path,
            regular,
            &self.options.include_patterns,
            &self.options.exclude_patterns,
        )
        .is_none()
        {
            return false;
        }
        self.reserve_file_read()
    }

    fn reserve_file_read(&mut self) -> bool {
        let coverage = &mut self.result.coverage;
        let next = coverage
            .reserved_read_bytes
            .saturating_add(coverage.max_file_read_bytes);
        if next > coverage.max_read_bytes {
            coverage.truncation.get_or_insert_with(|| {
                "content-read allowance reached; remaining preparation is uninspected".into()
            });
            coverage.read_limit_reached = true;
            return false;
        }
        coverage.reserved_read_bytes = next;
        true
    }
}

pub(crate) fn collect_literal_inventory(
    root: &Path,
    options: &AgenticSastInput,
    files: &[String],
    probe: &dyn Fn() -> Result<()>,
    progress: &mut dyn FnMut(usize),
) -> Result<AgenticInventory> {
    anyhow::ensure!(
        files.len() <= MAX_AGENTIC_INVENTORY_ENTRIES,
        "scoped preparation exceeds its accepted membership limit"
    );
    let mut walk = InventoryWalk::new(
        root,
        options,
        MAX_AGENTIC_INVENTORY_ENTRIES,
        probe,
        progress,
    );
    for file in files {
        probe()?;
        if walk.full() {
            walk.result.coverage.truncation.get_or_insert_with(|| {
                "snippet file/read limit reached; remaining scoped preparation is uninspected"
                    .into()
            });
            break;
        }
        walk.result.coverage.enumerated_entries += 1;
        (walk.progress)(walk.result.coverage.enumerated_entries);
        walk.add_literal_file(file);
    }
    Ok(walk.result)
}

impl InventoryWalk<'_> {
    fn add_literal_file(&mut self, file: &str) {
        if !self.reserve_file_read() {
            self.result.coverage.skipped_entries += 1;
            return;
        }
        let text = crate::bounded_file::read_source_text_prefix_within(
            self.root,
            &self.root.join(file),
            self.options.max_bytes_per_file,
        )
        .ok()
        .flatten();
        match text {
            Some(text) => {
                self.result.coverage.selected_files += 1;
                self.result.coverage.snippet_bytes += text.len();
                self.result.snippets.push((file.into(), text));
            }
            None => self.result.coverage.skipped_entries += 1,
        }
    }
}

#[cfg(test)]
mod tests;
