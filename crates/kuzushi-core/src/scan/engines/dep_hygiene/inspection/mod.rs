use super::*;
use crate::scan::engines::bounded_regular_files::{
    collect_regular_files, FileLimitBehavior, RegularFileWalkOptions,
};

mod documents;
mod reads;
mod receipt;

pub(crate) use receipt::{HygieneInspection, HygieneInspectionReceipt};

pub(crate) fn inspect_dependency_hygiene(
    target: &Path,
    cancellation: &ScanCancellation,
) -> Result<HygieneInspection> {
    let target = canonical_directory(target)?;
    let files = collect_regular_files(&target, cancellation, walk_options())?.files;
    let candidates = files
        .iter()
        .filter_map(|path| documents::manifest_kind(path).map(|kind| (path, kind)))
        .collect::<Vec<_>>();
    let mut inspection = HygieneInspection::new(&target, files.len(), candidates.len());
    inspection
        .receipt
        .gaps
        .extend(root_manifest_symlink_gaps(&target));
    for (path, kind) in candidates {
        cancellation.wait_if_paused();
        if cancellation.is_cancelled() {
            inspection
                .receipt
                .gaps
                .push("Cancelled; remaining manifests were not inspected.".into());
            break;
        }
        inspection.receipt.manifests_attempted += 1;
        match inspect_manifest(&target, path, kind, &mut inspection.receipt) {
            Ok(findings) => {
                inspection.receipt.manifests_inspected += 1;
                inspection.report.findings.extend(findings);
            }
            Err(error) => inspection
                .receipt
                .gaps
                .push(format!("{}: {error:#}", relative_display(&target, path))),
        }
    }
    inspection.report.count = inspection.report.findings.len();
    Ok(inspection)
}

fn inspect_manifest(
    root: &Path,
    path: &Path,
    kind: ManifestKind,
    receipt: &mut HygieneInspectionReceipt,
) -> Result<Vec<DepHygieneFinding>> {
    let raw = reads::read_manifest(root, path, receipt)?;
    documents::validate_document(kind, &raw)?;
    Ok(analyze_manifest(kind, path, &raw))
}

fn walk_options() -> RegularFileWalkOptions {
    RegularFileWalkOptions {
        operation: "dep-hygiene",
        max_entries: 100_000,
        max_files: 50_000,
        max_depth: 64,
        file_limit: FileLimitBehavior::Error,
        ignored_dir,
    }
}

fn ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".git"
                    | ".kuzushi"
                    | "node_modules"
                    | "vendor"
                    | "target"
                    | "dist"
                    | "build"
                    | ".venv"
                    | "venv"
            )
        })
}

fn root_manifest_symlink_gaps(root: &Path) -> Vec<String> {
    TARGET_MANIFESTS
        .iter()
        .filter_map(|kind| {
            let path = root.join(kind.file_name());
            let metadata = fs::symlink_metadata(&path).ok()?;
            metadata.file_type().is_symlink().then(|| {
                format!(
                    "{}: symlinked root manifest was not inspected",
                    kind.file_name()
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_inspection_refuses_before_collection() {
        let root = tempfile::tempdir().unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let error = inspect_dependency_hygiene(root.path(), &cancellation)
            .err()
            .unwrap();
        assert!(error.to_string().contains("cancelled"));
    }

    #[test]
    fn malformed_syntax_in_each_structured_format_is_an_inspection_gap() {
        let root = tempfile::tempdir().unwrap();
        for (name, raw) in [
            ("package.json", "["),
            ("Cargo.toml", "[invalid"),
            ("pubspec.yaml", "packages: ["),
            ("pom.xml", "<project>"),
        ] {
            fs::write(root.path().join(name), raw).unwrap();
        }
        let inspection =
            inspect_dependency_hygiene(root.path(), &ScanCancellation::default()).unwrap();
        assert_eq!(inspection.receipt.manifests_discovered, 4);
        assert_eq!(inspection.receipt.manifests_inspected, 0);
        assert_eq!(inspection.receipt.gaps.len(), 4);
        assert!(check_dependency_hygiene(root.path()).is_err());
        assert_eq!(inspection.to_tool_json()["status"], "partial");
    }

    #[cfg(unix)]
    #[test]
    fn stable_symlink_cycles_and_external_manifests_are_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("package.json");
        fs::write(&path, r#"{"dependencies":{"outside":"*"}}"#).unwrap();
        std::os::unix::fs::symlink(&path, root.path().join("package.json")).unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
        let inspection =
            inspect_dependency_hygiene(root.path(), &ScanCancellation::default()).unwrap();
        assert_eq!(inspection.receipt.manifests_discovered, 0);
        assert_eq!(inspection.report.count, 0);
        assert_eq!(inspection.receipt.gaps.len(), 1);
    }
}
