use serde::{Deserialize, Serialize};

pub(crate) const REQUIRED_X_RAY_MD: &str = "x-ray.md";
pub(crate) const REQUIRED_ENTRY_POINTS_MD: &str = "entry-points.md";
pub(crate) const REQUIRED_INVARIANTS_MD: &str = "invariants.md";
pub(crate) const REQUIRED_ARCHITECTURE_SVG: &str = "architecture.svg";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct XRayReportData {
    pub target: String,
    pub repo_name: String,
    pub runtime_mode: String,
    pub artifact_paths: XRayArtifactPaths,
    pub verdict: XRayVerdict,
    pub entry_point_counts: XRayEntryPointCounts,
    pub invariant_counts: XRayInvariantCounts,
    pub cost_usd: f64,
    /// False when only an observed subtotal is available because one of the
    /// provider calls did not report an exact monetary charge.
    #[serde(default)]
    pub cost_usd_exact: bool,
    /// Labelled local estimate of the whole run when some provider spend was
    /// unmetered; never folded into `cost_usd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XRayArtifactPaths {
    pub x_ray: String,
    pub entry_points: String,
    pub invariants: String,
    pub architecture_svg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XRayVerdict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XRayEntryPointCounts {
    pub permissionless: usize,
    pub role_gated: usize,
    pub admin_only: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct XRayInvariantCounts {
    pub global: usize,
    pub integration: usize,
    pub cross_chain: usize,
    pub economic: usize,
    pub total: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct XRayArtifactContent {
    pub(crate) x_ray_markdown: String,
    pub(crate) entry_points_markdown: String,
    pub(crate) invariants_markdown: String,
    pub(crate) architecture_svg: String,
}
