use super::MAX_COVERAGE_PREVIEW;
use crate::workspace::InventoryInspection;

pub(super) fn details(inspection: &InventoryInspection) -> Vec<String> {
    let mut lines = vec![format!(
        "Inspection bounds: {} entries; {} total bytes; {} bytes per file.",
        inspection.max_entries,
        inspection.max_inspected_bytes,
        inspection.max_file_inspection_bytes
    )];
    lines.extend(
        inspection
            .omitted_paths
            .iter()
            .take(MAX_COVERAGE_PREVIEW)
            .map(|row| format!("Omitted: {}. Reason: {}.", row.path, row.reason)),
    );
    lines.extend(not_shown(inspection.omitted_paths.len(), "omitted paths"));
    lines.extend(
        inspection
            .truncated_files
            .iter()
            .take(MAX_COVERAGE_PREVIEW)
            .map(|path| {
                format!(
                    "Prefix only: {path}. Inspected at most {} bytes.",
                    inspection.max_file_inspection_bytes
                )
            }),
    );
    lines.extend(not_shown(
        inspection.truncated_files.len(),
        "prefix-limited files",
    ));
    lines
}

fn not_shown(total: usize, kind: &str) -> Option<String> {
    (total > MAX_COVERAGE_PREVIEW).then(|| format!(
        "Additional {kind}: {}. The full recorded list remains in the inventory artifact; this preview shows the first {MAX_COVERAGE_PREVIEW}.",
        total - MAX_COVERAGE_PREVIEW
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::InventoryPathClassification;

    fn inspection() -> InventoryInspection {
        InventoryInspection {
            enumeration_complete: None,
            files: vec!["source.rs".into()],
            enumeration: "git-index".into(),
            entries: 1,
            inspected_bytes: 262144,
            max_entries: 100000,
            max_inspected_bytes: 536870912,
            max_file_inspection_bytes: 262144,
            omitted_paths: vec![InventoryPathClassification {
                path: "vendor".into(),
                kind: "omitted".into(),
                reason: "ignored directory".into(),
            }],
            truncated_files: vec!["source.rs".into()],
        }
    }

    #[test]
    fn limits_name_omitted_material_reasons_prefixes_and_all_bounds() {
        let lines = details(&inspection());
        assert_eq!(
            lines,
            vec![
                "Inspection bounds: 100000 entries; 536870912 total bytes; 262144 bytes per file.",
                "Omitted: vendor. Reason: ignored directory.",
                "Prefix only: source.rs. Inspected at most 262144 bytes.",
            ]
        );
    }

    #[test]
    fn large_disclosures_keep_exact_counts_without_unbounded_preview_text() {
        let mut receipt = inspection();
        receipt.omitted_paths = (0..130)
            .map(|index| InventoryPathClassification {
                path: format!("omitted-{index}"),
                kind: "omitted".into(),
                reason: "ignored".into(),
            })
            .collect();
        receipt.truncated_files = (0..129).map(|index| format!("large-{index}.rs")).collect();
        let lines = details(&receipt);
        assert_eq!(lines.len(), 259);
        assert!(lines
            .iter()
            .any(|line| line.starts_with("Additional omitted paths: 2.")));
        assert!(lines
            .iter()
            .any(|line| line.starts_with("Additional prefix-limited files: 1.")));
        assert!(!lines
            .iter()
            .any(|line| line.contains("omitted-128") || line.contains("large-128.rs")));
    }

    #[test]
    fn no_omissions_or_prefixes_do_not_invent_coverage_gaps() {
        let mut receipt = inspection();
        receipt.omitted_paths.clear();
        receipt.truncated_files.clear();
        assert_eq!(details(&receipt).len(), 1);
    }
}
