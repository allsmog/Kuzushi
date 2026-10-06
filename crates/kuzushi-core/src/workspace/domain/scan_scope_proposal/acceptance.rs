use super::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopeCoverageApproval {
    pub inventory_limitations: bool,
    pub overlapping_discovery: bool,
    pub exclusions: bool,
}

impl ScanScopeCoverage {
    /// Scope acceptance never infers consent to omitted or duplicate work.
    pub fn ensure_acceptable(&self, approval: &ScopeCoverageApproval) -> Result<()> {
        anyhow::ensure!(
            self.uncovered_files.total == 0,
            "uncovered inventoried files remain; add a residual scope or explicitly exclude them"
        );
        require_approval(self.inventory_limited, approval.inventory_limitations,
            "inventory limitations require explicit acknowledgement; no complete repository coverage claim is available")?;
        require_approval(
            self.overlaps.total > 0,
            approval.overlapping_discovery,
            "overlapping discovery requires explicit approval of duplicate work",
        )?;
        require_approval(
            self.excluded_files.total > 0,
            approval.exclusions,
            "excluded files require explicit acknowledgement",
        )
    }
}

fn require_approval(condition: bool, approved: bool, message: &str) -> Result<()> {
    anyhow::ensure!(!condition || approved, "{message}");
    Ok(())
}
