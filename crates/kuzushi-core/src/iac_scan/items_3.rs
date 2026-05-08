use super::prelude::*;
use super::*;

#[derive(Debug, Clone)]
pub struct IacScanScanner {
    pub options: IacScanOptions,
}

impl Default for IacScanScanner {
    fn default() -> Self {
        Self {
            options: IacScanOptions::default(),
        }
    }
}

impl IacScanScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            options: IacScanOptions::from_tool_input(input)?,
        })
    }
}

impl ScanEngine for IacScanScanner {
    fn id(&self) -> &'static str {
        "iac-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_iac(target, &self.options, cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(IacScanFinding::to_core_finding)
            .collect())
    }
}

pub fn scan_iac(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
) -> Result<IacScanReport> {
    let target = canonical_directory(target)?;
    let mut files = Vec::new();
    collect_iac_files(&target, &target, options, &mut files)?;
    files.sort();

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;

    for file in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("iac-scan scan cancelled");
        }

        let metadata = match fs::metadata(&file) {
            Ok(metadata) => metadata,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        if metadata.len() > options.max_file_bytes {
            files_skipped += 1;
            continue;
        }

        let raw = match fs::read_to_string(&file) {
            Ok(raw) => raw,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        files_scanned += 1;

        match classify_iac_file(&target, &file) {
            Some(IacScanKind::Dockerfile) if options.kind.includes(IacScanKind::Dockerfile) => {
                findings.extend(analyze_dockerfile(&target, &file, &raw));
            }
            Some(IacScanKind::GithubActions)
                if options.kind.includes(IacScanKind::GithubActions) =>
            {
                findings.extend(analyze_github_actions(&target, &file, &raw));
            }
            Some(IacScanKind::Terraform) if options.kind.includes(IacScanKind::Terraform) => {
                findings.extend(analyze_terraform(&target, &file, &raw));
            }
            _ => {}
        }
    }

    Ok(IacScanReport {
        target: target.display().to_string(),
        kind: options.kind,
        findings,
        files_scanned,
        files_skipped,
    })
}
