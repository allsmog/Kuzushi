use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_PROMPT_TREE_DEPTH: usize = 64;
const MAX_PROMPT_TREE_ENTRIES: usize = 8_192;

pub(super) fn validate(root: &Path) -> Result<()> {
    reject_generated_tree_policy(root)?;
    reject_prompt_tree_policies(root)
}

fn reject_generated_tree_policy(root: &Path) -> Result<()> {
    let path = root.join(".kuzushi/v3/.gitignore");
    reject_policy_node(
        &path,
        "Generated state subtree must not contain descendant Git ignore policy",
    )
}

fn reject_prompt_tree_policies(root: &Path) -> Result<()> {
    let prompt_root = root.join(".kuzushi/prompts");
    let mut pending = VecDeque::from([(prompt_root, 0_usize)]);
    let mut entries_seen = 0_usize;
    while let Some((directory, depth)) = pending.pop_front() {
        if !is_real_directory(&directory)? {
            continue;
        }
        for entry in bounded_entries(&directory, &mut entries_seen)? {
            inspect_prompt_entry(entry, depth, &mut pending)?;
        }
    }
    Ok(())
}

fn inspect_prompt_entry(
    entry: fs::DirEntry,
    parent_depth: usize,
    pending: &mut VecDeque<(PathBuf, usize)>,
) -> Result<()> {
    let path = entry.path();
    if entry.file_name() == OsStr::new(".gitignore") {
        anyhow::bail!(
            "Trackable prompt tree must not contain descendant Git ignore policy: {}",
            path.display()
        );
    }
    let file_type = entry
        .file_type()
        .with_context(|| format!("Could not inspect prompt tree entry {}", path.display()))?;
    if file_type.is_dir() {
        let depth = parent_depth.saturating_add(1);
        anyhow::ensure!(
            depth <= MAX_PROMPT_TREE_DEPTH,
            "Prompt policy validation exceeded its {MAX_PROMPT_TREE_DEPTH}-level depth limit at {}",
            path.display()
        );
        pending.push_back((path, depth));
    }
    Ok(())
}

fn bounded_entries(path: &Path, entries_seen: &mut usize) -> Result<Vec<fs::DirEntry>> {
    let remaining = MAX_PROMPT_TREE_ENTRIES.saturating_sub(*entries_seen);
    let entries = fs::read_dir(path)
        .with_context(|| format!("Could not read prompt tree directory {}", path.display()))?
        .take(remaining.saturating_add(1))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| {
            format!(
                "Could not enumerate prompt tree directory {}",
                path.display()
            )
        })?;
    anyhow::ensure!(
        entries.len() <= remaining,
        "Prompt policy validation exceeded its {MAX_PROMPT_TREE_ENTRIES}-entry limit"
    );
    *entries_seen += entries.len();
    Ok(entries)
}

fn is_real_directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("Could not inspect prompt tree {}", path.display()))
        }
    }
}

fn reject_policy_node(path: &Path, message: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
        Ok(_) => anyhow::bail!("{message}: {}", path.display()),
    }
}
