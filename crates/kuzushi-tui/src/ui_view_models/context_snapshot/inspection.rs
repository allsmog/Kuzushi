use kuzushi_core::context::{ContextEnumeration, ContextSnapshotInspection};

pub(super) fn inspection_lines(inspection: Option<&ContextSnapshotInspection>) -> Vec<String> {
    let Some(receipt) = inspection else {
        return vec![
            "Inventory inspection extent: unknown on this snapshot. Rebuild context to record it."
                .into(),
        ];
    };
    vec![
        enumeration_line(receipt.enumeration).into(),
        format!("Sample: {} of {} enumerated files; this does not establish full content coverage.", receipt.sampled_files, receipt.enumerated_files),
        format!("Inventory entries: {} / {}. Inspected bytes: {} / {}; per-file inspection cap {} bytes.", receipt.entries, receipt.max_entries, receipt.inspected_bytes, receipt.max_inspected_bytes, receipt.max_file_inspection_bytes),
        format!("Recorded omissions: {} paths. Files inspected only in part: {}. Inventory: {}. Provenance and manifest checks have separate work.", receipt.omitted_paths, receipt.truncated_files, if receipt.truncated { "partial" } else { "within its recorded enumeration" }),
    ]
}

fn enumeration_line(enumeration: ContextEnumeration) -> &'static str {
    match enumeration {
        ContextEnumeration::GitIndex => {
            "Enumeration: Git tracked files. Untracked source is outside this inventory."
        }
        ContextEnumeration::Filesystem => {
            "Enumeration: bounded filesystem inventory. Ignored and generated paths can be omitted."
        }
        ContextEnumeration::Interrupted => {
            "Enumeration: canceled during Git path acquisition. No source files were inspected."
        }
    }
}

#[cfg(test)]
mod tests;
