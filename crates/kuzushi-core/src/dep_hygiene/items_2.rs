use super::prelude::*;
use super::*;

impl DepHygieneFinding {
    pub(crate) fn new(
        manifest: ManifestKind,
        file_path: &Path,
        package_name: impl Into<String>,
        raw_constraint: impl Into<String>,
        severity: DepHygieneSeverity,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            manifest: manifest.file_name().to_string(),
            file_path: file_path.display().to_string(),
            package_name: package_name.into(),
            raw_constraint: raw_constraint.into(),
            severity,
            reason: reason.into(),
        }
    }

    pub(crate) fn to_core_finding(&self, target: &Path) -> Finding {
        let absolute_path = Path::new(&self.file_path);
        let file_path = absolute_path
            .strip_prefix(target)
            .unwrap_or(absolute_path)
            .display()
            .to_string();
        let constraint = if self.raw_constraint.is_empty() {
            "(empty)"
        } else {
            &self.raw_constraint
        };
        let message = format!(
            "{}@{} in {}: {}",
            self.package_name, constraint, self.manifest, self.reason
        );
        Finding::new_tool(
            "dep-hygiene",
            format!("dep-hygiene/{}", self.manifest.replace('.', "-")),
            file_path,
            1,
            None,
            self.severity.to_core_severity(),
            message,
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DepHygieneSeverity {
    Low,
    Medium,
    High,
}

impl DepHygieneSeverity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub(crate) fn to_core_severity(self) -> Severity {
        match self {
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DepHygieneScanner;

impl ScanEngine for DepHygieneScanner {
    fn id(&self) -> &'static str {
        "dep-hygiene"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("dep-hygiene scan cancelled");
        }

        let report = check_dependency_hygiene(target)?;
        Ok(report
            .findings
            .iter()
            .map(|finding| finding.to_core_finding(Path::new(&report.target)))
            .collect())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CargoAuditScanner;

impl CargoAuditScanner {
    /// Probe whether `cargo audit` is callable in the current environment.
    /// Returns `false` on any spawn or non-success exit, including when
    /// `cargo` itself is missing.
    pub fn binary_available() -> bool {
        Command::new("cargo")
            .args(["audit", "--version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
