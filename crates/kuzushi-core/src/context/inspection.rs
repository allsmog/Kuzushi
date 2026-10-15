//! Recorded inspection extent, independent of freshness or finding verdicts.
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextEnumeration {
    GitIndex,
    Filesystem,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshotInspection {
    pub enumeration: ContextEnumeration,
    pub entries: u64,
    pub max_entries: u64,
    pub inspected_bytes: u64,
    pub max_inspected_bytes: u64,
    pub max_file_inspection_bytes: u64,
    pub enumerated_files: usize,
    pub sampled_files: usize,
    pub omitted_paths: usize,
    pub truncated_files: usize,
    pub truncated: bool,
}

pub fn context_snapshot_inspection(snapshot: &Value) -> Option<ContextSnapshotInspection> {
    let value = snapshot.pointer("/repositoryInventory/inspection")?;
    let enumeration = read_enumeration(value["enumeration"].as_str()?)?;
    Some(ContextSnapshotInspection {
        enumeration,
        entries: value["entries"].as_u64()?,
        max_entries: value["max_entries"].as_u64()?,
        inspected_bytes: value["inspected_bytes"].as_u64()?,
        max_inspected_bytes: value["max_inspected_bytes"].as_u64()?,
        max_file_inspection_bytes: value["max_file_inspection_bytes"].as_u64()?,
        enumerated_files: value["files"].as_array()?.len(),
        sampled_files: snapshot["filesSample"].as_array()?.len(),
        omitted_paths: value["omitted_paths"].as_array()?.len(),
        truncated_files: value["truncated_files"].as_array()?.len(),
        truncated: snapshot
            .pointer("/repositoryInventory/truncation")
            .is_some_and(|v| !v.is_null()),
    })
}

fn read_enumeration(value: &str) -> Option<ContextEnumeration> {
    match value {
        "git-index" => Some(ContextEnumeration::GitIndex),
        "filesystem" => Some(ContextEnumeration::Filesystem),
        "interrupted" => Some(ContextEnumeration::Interrupted),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
