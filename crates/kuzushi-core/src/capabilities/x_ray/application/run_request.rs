use super::*;

#[derive(Debug, Clone)]
pub(crate) struct XRayRunInput {
    pub(crate) target: PathBuf,
    pub(crate) repo_name: String,
    pub(crate) model: String,
    pub(crate) effort: Option<String>,
    pub(crate) max_budget_usd: Option<f64>,
    pub(crate) kb_context: ArtifactKnowledgePromptContext,
}

pub(crate) const X_RAY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Pashov X-Ray report generator.
Return only JSON with string fields:
{"xRayMarkdown":"...","entryPointsMarkdown":"...","invariantsMarkdown":"...","architectureSvg":"<svg ...>"}.
Do not choose a model or runtime; use the model provided by the caller."#;

pub(crate) fn x_ray_artifact_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "required": [
            "xRayMarkdown",
            "entryPointsMarkdown",
            "invariantsMarkdown",
            "architectureSvg"
        ],
        "additionalProperties": true,
        "properties": {
            "xRayMarkdown": {"type": "string"},
            "entryPointsMarkdown": {"type": "string"},
            "invariantsMarkdown": {"type": "string"},
            "architectureSvg": {"type": "string"}
        }
    })
}

pub(crate) fn build_x_ray_prompt(input: &XRayRunInput) -> String {
    let budget_line = input
        .max_budget_usd
        .map(|value| format!("Budget cap requested by operator: ${value:.4}."))
        .unwrap_or_else(|| "No explicit budget cap was supplied.".to_string());
    let effort_line = input
        .effort
        .as_deref()
        .map(|value| format!("Reasoning effort requested by operator: {value}."))
        .unwrap_or_else(|| "No reasoning effort override was supplied.".to_string());

    format!(
        "Generate a Pashov X-Ray pre-audit report for this repository.\n\
         Repository name: {repo_name}\n\
         Repository path: {repo_path}\n\
         {budget_line}\n\
         {effort_line}\n\n\
         Return a single JSON object with these exact string fields:\n\
         - xRayMarkdown: Markdown for x-ray/x-ray.md, including a `## X-Ray Verdict` section with one of FORTIFIED, HARDENED, ADEQUATE, READY, WATCH, FRAGILE, EXPOSED.\n\
         - entryPointsMarkdown: Markdown for x-ray/entry-points.md, including a summary line with total, permissionless, role-gated, and admin-only counts when possible.\n\
         - invariantsMarkdown: Markdown for x-ray/invariants.md, using IDs such as G-1, I-1, X-1, and E-1 when applicable.\n\
         - architectureSvg: A complete SVG document for x-ray/architecture.svg.\n\n\
         {kb_block}\n\n\
         Read the repository contents conceptually through the pi-agent-core runtime context and keep the output grounded in concrete files and entry points.",
        repo_name = input.repo_name,
        repo_path = input.target.display(),
        kb_block = input.kb_context.render_prompt_block()
    )
}
