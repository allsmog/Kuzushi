use super::*;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct CoverageReceipt {
    paths: Option<ScannedPaths>,
}

#[derive(Deserialize)]
struct ScannedPaths {
    scanned: Vec<String>,
}

pub(super) fn exact_file_coverage(
    root: &Path,
    files: &[String],
    stdout: &[u8],
) -> Result<Vec<String>> {
    let receipt: CoverageReceipt = match serde_json::from_slice(stdout) {
        Ok(receipt) => receipt,
        Err(_) => return Ok(vec!["Semgrep did not provide a valid file-coverage receipt; selected files cannot be reported as fully analyzed".into()]),
    };
    let Some(paths) = receipt.paths else {
        return Ok(vec!["Semgrep did not provide a file-coverage receipt; selected files cannot be reported as fully analyzed".into()]);
    };
    let scanned = paths
        .scanned
        .iter()
        .map(|file| relative_scanned_path(root, file))
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = files.iter().cloned().collect::<BTreeSet<_>>();
    anyhow::ensure!(
        scanned.is_subset(&expected),
        "Semgrep reported source outside accepted file membership"
    );
    let missing = expected.difference(&scanned).count();
    if missing == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![format!("Semgrep did not report scanning {missing} selected files; those files cannot be considered analyzed")])
}

fn relative_scanned_path(root: &Path, file: &str) -> Result<String> {
    let path = Path::new(file);
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .context("Semgrep reported source outside the selected repository")?
            .to_string_lossy()
            .to_string()
    } else {
        file.to_string()
    };
    normalized_scan_path(&relative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_malformed_file_receipts_never_establish_complete_coverage() {
        let files = ["selected.py".into()];
        for receipt in [
            json!({}),
            json!({"paths":{}}),
            json!({"paths":{"scanned":"invalid"}}),
        ] {
            assert!(!exact_file_coverage(
                Path::new("/repo"),
                &files,
                &serde_json::to_vec(&receipt).unwrap()
            )
            .unwrap()
            .is_empty());
        }
    }

    #[test]
    fn skipped_members_remain_partial_and_outside_source_is_refused() {
        let files = ["selected.py".into(), "skipped.py".into()];
        let receipt = br#"{"paths":{"scanned":["./selected.py"]}}"#;
        assert!(
            exact_file_coverage(Path::new("/repo"), &files, receipt).unwrap()[0]
                .contains("1 selected files")
        );
        for file in ["outside.py", "../outside.py", "/outside.py"] {
            let receipt = serde_json::to_vec(&json!({"paths":{"scanned":[file]}})).unwrap();
            assert!(exact_file_coverage(Path::new("/repo"), &files, &receipt).is_err());
        }
        assert!(exact_file_coverage(
            Path::new("/repo"),
            &["selected.py".into()],
            br#"{"paths":{"scanned":["/repo/selected.py"]}}"#
        )
        .unwrap()
        .is_empty());
    }
}
