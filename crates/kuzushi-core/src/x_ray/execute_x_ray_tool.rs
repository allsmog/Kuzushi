use super::*;

pub(crate) const REQUIRED_X_RAY_MD: &str = "x-ray.md";

pub(crate) const REQUIRED_ENTRY_POINTS_MD: &str = "entry-points.md";

pub(crate) const REQUIRED_INVARIANTS_MD: &str = "invariants.md";

pub(crate) const REQUIRED_ARCHITECTURE_SVG: &str = "architecture.svg";

pub fn execute_x_ray_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "x-ray:run" | "x-ray:x-ray" => run_x_ray(input, ctx, runtime),
        "x-ray:read" => read_x_ray(input, ctx),
        other => anyhow::bail!("unknown x-ray tool {other:?}"),
    }
}

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
pub(crate) struct XRayRunInput {
    pub(crate) target: PathBuf,
    pub(crate) repo_name: String,
    pub(crate) model: String,
    pub(crate) effort: Option<String>,
    pub(crate) max_budget_usd: Option<f64>,
    pub(crate) kb_context: ArtifactKnowledgePromptContext,
}

#[derive(Debug, Clone)]
pub(crate) struct XRayArtifactContent {
    pub(crate) x_ray_markdown: String,
    pub(crate) entry_points_markdown: String,
    pub(crate) invariants_markdown: String,
    pub(crate) architecture_svg: String,
}
