use super::files::is_lead_source_path;
use crate::workspace::inventory::{collect_source_prefixes, SourcePrefixLimits, SourcePrefixes};
use anyhow::Result;
use std::path::Path;

pub(super) fn collect(
    root: &Path,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<SourcePrefixes> {
    let mut index = collect_source_prefixes(
        root,
        SourcePrefixLimits {
            max_files: 6000,
            max_bytes: 16 * 1024 * 1024,
            max_file_bytes: 256 * 1024,
        },
        &is_lead_source_path,
        progress,
        canceled,
    )?;
    index.coverage["confidenceMeaning"] =
        serde_json::json!("Keyword overlap only; not vulnerability validity or accepted context.");
    Ok(index)
}

pub(super) fn ensure_active(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(
        !canceled(),
        "threat-leads build canceled; existing artifacts were preserved"
    );
    Ok(())
}
