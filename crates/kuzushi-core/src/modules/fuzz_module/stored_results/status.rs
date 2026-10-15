use super::*;
use std::collections::BTreeMap;

pub(super) const MAX_ENTRIES: usize = 10_000;
pub(super) const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(super) struct StoredWorkspace {
    pub initialized: bool,
    pub sinks_present: bool,
    pub targets: Vec<String>,
    pub built: Vec<String>,
    pub workorders: Vec<String>,
}

#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredCounts {
    pub verified: usize,
    pub total: usize,
    pub malformed_rows: usize,
}

pub(super) fn workspace(root: &Path, active: &dyn Fn() -> Result<()>) -> Result<StoredWorkspace> {
    active()?;
    let Some(root) = existing_root(root)? else {
        return Ok(StoredWorkspace::default());
    };
    let mut snapshot = StoredWorkspace {
        initialized: marker(&root, Path::new("workspace.json"))?,
        sinks_present: marker(&root, Path::new("data/sink-scan.jsonl"))?
            || marker(&root, Path::new("data/sinks.jsonl"))?,
        ..Default::default()
    };
    read_targets(&root, &mut snapshot, active)?;
    snapshot.targets.sort();
    snapshot.built.sort();
    snapshot.workorders.sort();
    Ok(snapshot)
}

fn existing_root(root: &Path) -> Result<Option<PathBuf>> {
    match root.canonicalize() {
        Ok(path) => {
            anyhow::ensure!(
                path.is_dir(),
                "Stored engine root is not a directory: {}",
                root.display()
            );
            Ok(Some(path))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect stored engine root {}", root.display())),
    }
}

fn marker(root: &Path, relative: &Path) -> Result<bool> {
    match crate::bounded_file::open_regular_file_within(root, &root.join(relative)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect stored marker {}", relative.display())),
    }
}

fn read_targets(
    root: &Path,
    snapshot: &mut StoredWorkspace,
    active: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let entries = match crate::bounded_file::read_dir_within(root, &root.join("targets/c")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Could not read stored target directory"),
    };
    collect_targets(root, entries, snapshot, active)
}

fn collect_targets(
    root: &Path,
    entries: std::fs::ReadDir,
    snapshot: &mut StoredWorkspace,
    active: &dyn Fn() -> Result<()>,
) -> Result<()> {
    for (index, entry) in entries.enumerate() {
        active()?;
        anyhow::ensure!(
            index < MAX_ENTRIES,
            "Stored target directory exceeds the {MAX_ENTRIES}-entry inspection limit"
        );
        let entry = entry.context("Could not read stored target entry")?;
        anyhow::ensure!(
            !entry.file_type()?.is_symlink(),
            "Stored target entry is a symlink; status is incomplete"
        );
        collect_target(root, &entry, snapshot)?;
    }
    Ok(())
}

fn collect_target(
    root: &Path,
    entry: &std::fs::DirEntry,
    snapshot: &mut StoredWorkspace,
) -> Result<()> {
    if !entry.file_type()?.is_dir() {
        return Ok(());
    }
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| anyhow::anyhow!("Stored target name is not UTF-8"))?;
    let relative = Path::new("targets/c").join(&name);
    if !marker(root, &relative.join("harness.cpp"))? {
        return Ok(());
    }
    snapshot.targets.push(name.clone());
    collect_target_markers(root, &relative, name, snapshot)
}

fn collect_target_markers(
    root: &Path,
    relative: &Path,
    name: String,
    snapshot: &mut StoredWorkspace,
) -> Result<()> {
    if marker(root, &Path::new("bin").join(&name).join("fuzzer"))? {
        snapshot.built.push(name.clone());
    }
    if marker(root, &relative.join(".localfuzz/workorder.json"))? {
        snapshot.workorders.push(name);
    }
    Ok(())
}

pub(super) fn index(root: &Path, active: &dyn Fn() -> Result<()>) -> Result<Option<StoredCounts>> {
    active()?;
    let Some(root) = existing_root(root)? else {
        return Ok(None);
    };
    let body = match crate::bounded_file::read_utf8_text_within(
        &root,
        &root.join("findings-index.jsonl"),
        MAX_INDEX_BYTES,
    ) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Could not read stored findings index"),
    };
    fold_counts(&body, active).map(Some)
}

fn fold_counts(body: &str, active: &dyn Fn() -> Result<()>) -> Result<StoredCounts> {
    let mut recorded = BTreeMap::new();
    let mut malformed_rows = 0;
    for (index, line) in body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        active()?;
        anyhow::ensure!(
            index < MAX_ENTRIES,
            "Stored findings index exceeds the {MAX_ENTRIES}-row inspection limit"
        );
        count_row(line, &mut recorded, &mut malformed_rows);
    }
    Ok(StoredCounts {
        verified: recorded.values().filter(|value| **value).count(),
        total: recorded.len(),
        malformed_rows,
    })
}

fn count_row(line: &str, recorded: &mut BTreeMap<String, bool>, malformed: &mut usize) {
    match index_rows::parse_index_line(line) {
        Some(index_rows::IndexEvent::Recorded(row)) => {
            recorded.insert(row.finding_id, row.verified);
        }
        Some(_) => {}
        None => *malformed += 1,
    }
}

#[cfg(test)]
mod tests;
