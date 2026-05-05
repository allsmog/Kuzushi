use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};

const REQUIRED_X_RAY_MD: &str = "x-ray.md";
const REQUIRED_ENTRY_POINTS_MD: &str = "entry-points.md";
const REQUIRED_INVARIANTS_MD: &str = "invariants.md";
const REQUIRED_ARCHITECTURE_SVG: &str = "architecture.svg";

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
struct XRayRunInput {
    target: PathBuf,
    repo_name: String,
    model: String,
    effort: Option<String>,
    max_budget_usd: Option<f64>,
}

#[derive(Debug, Clone)]
struct XRayArtifactContent {
    x_ray_markdown: String,
    entry_points_markdown: String,
    invariants_markdown: String,
    architecture_svg: String,
}

fn run_x_ray(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = runtime.context(
        "x-ray:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let input = parse_run_input(&input, ctx)?;
    let prompt = build_x_ray_prompt(&input);
    let response = runtime.query_blocking(AgentQueryRequest {
        model: input.model.clone(),
        cwd: input.target.clone(),
        system_prompt: X_RAY_SYSTEM_PROMPT.to_string(),
        prompt,
    })?;

    match parse_artifact_content_response(&response.structured, &response.text) {
        Ok(content) => write_x_ray_artifacts(&input.target, content)?,
        Err(parse_error) => {
            if !required_artifacts_exist(&input.target) {
                anyhow::bail!(
                    "x-ray:run expected pi-agent-core to return JSON artifact content and no existing complete x-ray/ artifact set was found: {parse_error}"
                );
            }
        }
    }

    let data =
        read_x_ray_report_artifacts(&input.target, Some(&input.repo_name), "pi-agent-core", 0.0)?;
    Ok(json!({
        "ok": true,
        "output": render_x_ray_run_summary(&data),
        "data": data,
        "costUsd": 0.0,
    }))
}

fn read_x_ray(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let data = read_x_ray_report_artifacts(&target, Some(&repo_name), "rust", 0.0)?;
    Ok(json!({
        "ok": true,
        "output": render_x_ray_read_summary(&data),
        "data": data,
    }))
}

pub fn read_x_ray_report_artifacts(
    repo_root: &Path,
    repo_name: Option<&str>,
    runtime_mode: &str,
    cost_usd: f64,
) -> Result<XRayReportData> {
    let repo_root = canonicalize_dir(repo_root)?;
    let artifact_dir = repo_root.join("x-ray");
    let paths = XRayArtifactPaths {
        x_ray: artifact_dir.join(REQUIRED_X_RAY_MD).display().to_string(),
        entry_points: artifact_dir
            .join(REQUIRED_ENTRY_POINTS_MD)
            .display()
            .to_string(),
        invariants: artifact_dir
            .join(REQUIRED_INVARIANTS_MD)
            .display()
            .to_string(),
        architecture_svg: artifact_dir
            .join(REQUIRED_ARCHITECTURE_SVG)
            .display()
            .to_string(),
    };

    let required = [
        PathBuf::from(&paths.x_ray),
        PathBuf::from(&paths.entry_points),
        PathBuf::from(&paths.invariants),
        PathBuf::from(&paths.architecture_svg),
    ];
    let missing = required
        .iter()
        .filter(|candidate| !candidate.exists())
        .map(|candidate| candidate.display().to_string())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "X-Ray report is missing required artifact(s): {}",
            missing.join(", ")
        );
    }

    let x_ray_markdown = fs::read_to_string(&paths.x_ray)
        .with_context(|| format!("Unable to read {}", paths.x_ray))?;
    let entry_points_markdown = fs::read_to_string(&paths.entry_points)
        .with_context(|| format!("Unable to read {}", paths.entry_points))?;
    let invariants_markdown = fs::read_to_string(&paths.invariants)
        .with_context(|| format!("Unable to read {}", paths.invariants))?;

    Ok(XRayReportData {
        target: repo_root.display().to_string(),
        repo_name: repo_name
            .map(ToString::to_string)
            .unwrap_or_else(|| self::repo_name(&repo_root)),
        runtime_mode: runtime_mode.to_string(),
        artifact_paths: paths,
        verdict: parse_verdict(&x_ray_markdown),
        entry_point_counts: parse_entry_point_counts(&entry_points_markdown),
        invariant_counts: parse_invariant_counts(&invariants_markdown),
        cost_usd,
    })
}

fn parse_run_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<XRayRunInput> {
    let target = resolve_target(input, ctx)?;
    let repo_name = repo_name(&target);
    let model = optional_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context("x-ray:run requires an explicit model in config.toml, KUZUSHI_MODEL, or the tool input; Kuzushi will not choose a fallback model")?;
    let effort = optional_string(input, "effort")?;
    let max_budget_usd = input
        .get("maxBudgetUsd")
        .or_else(|| input.get("max_budget_usd"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0);

    Ok(XRayRunInput {
        target,
        repo_name,
        model,
        effort,
        max_budget_usd,
    })
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = optional_string(input, "target")? {
        return canonicalize_dir(Path::new(&target));
    }

    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }

    canonicalize_dir(Path::new("."))
}

fn canonicalize_dir(path: &Path) -> Result<PathBuf> {
    let root = fs::canonicalize(path)
        .with_context(|| format!("Could not resolve target {}", path.display()))?;
    if !root.is_dir() {
        anyhow::bail!("Target must be a directory: {}", root.display());
    }
    Ok(root)
}

fn optional_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Some(_) => anyhow::bail!("x-ray:run {key} must be a string"),
        None => Ok(None),
    }
}

const X_RAY_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Pashov X-Ray report generator.
Return only JSON with string fields:
{"xRayMarkdown":"...","entryPointsMarkdown":"...","invariantsMarkdown":"...","architectureSvg":"<svg ...>"}.
Do not choose a model or runtime; use the model provided by the caller."#;

fn build_x_ray_prompt(input: &XRayRunInput) -> String {
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
         Read the repository contents conceptually through the pi-agent-core runtime context and keep the output grounded in concrete files and entry points.",
        repo_name = input.repo_name,
        repo_path = input.target.display()
    )
}

fn parse_artifact_content_response(
    structured: &Option<Value>,
    text: &str,
) -> Result<XRayArtifactContent> {
    if let Some(value) = structured {
        if let Ok(content) = XRayArtifactContent::from_value(value) {
            return Ok(content);
        }
    }

    let value = parse_json_object_from_text(text)?;
    XRayArtifactContent::from_value(&value)
}

impl XRayArtifactContent {
    fn from_value(value: &Value) -> Result<Self> {
        let x_ray_markdown = string_any(value, &["xRayMarkdown", "xRay", "x_ray", "x-ray.md"])
            .context("missing xRayMarkdown artifact content")?;
        let entry_points_markdown = string_any(
            value,
            &[
                "entryPointsMarkdown",
                "entryPoints",
                "entry_points",
                "entry-points.md",
            ],
        )
        .context("missing entryPointsMarkdown artifact content")?;
        let invariants_markdown = string_any(
            value,
            &[
                "invariantsMarkdown",
                "invariants",
                "invariants_md",
                "invariants.md",
            ],
        )
        .context("missing invariantsMarkdown artifact content")?;
        let architecture_svg = string_any(
            value,
            &[
                "architectureSvg",
                "architectureSVG",
                "architecture",
                "architecture.svg",
            ],
        )
        .context("missing architectureSvg artifact content")?;

        Ok(Self {
            x_ray_markdown,
            entry_points_markdown,
            invariants_markdown,
            architecture_svg,
        })
    }
}

fn string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_str())
        .map(ToString::to_string)
        .filter(|value| !value.trim().is_empty())
}

fn parse_json_object_from_text(text: &str) -> Result<Value> {
    let trimmed = text.trim();
    let candidate = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|without_prefix| without_prefix.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);

    if let Ok(value) = serde_json::from_str::<Value>(candidate) {
        return Ok(value);
    }

    let start = candidate
        .find('{')
        .context("pi-agent-core response did not contain a JSON object")?;
    let end = candidate
        .rfind('}')
        .context("pi-agent-core response did not contain a complete JSON object")?;
    serde_json::from_str(&candidate[start..=end])
        .context("Could not parse pi-agent-core JSON artifact response")
}

fn write_x_ray_artifacts(repo_root: &Path, content: XRayArtifactContent) -> Result<()> {
    let artifact_dir = repo_root.join("x-ray");
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("Could not create {}", artifact_dir.display()))?;
    fs::write(artifact_dir.join(REQUIRED_X_RAY_MD), content.x_ray_markdown)
        .context("Could not write x-ray.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_ENTRY_POINTS_MD),
        content.entry_points_markdown,
    )
    .context("Could not write entry-points.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_INVARIANTS_MD),
        content.invariants_markdown,
    )
    .context("Could not write invariants.md")?;
    fs::write(
        artifact_dir.join(REQUIRED_ARCHITECTURE_SVG),
        content.architecture_svg,
    )
    .context("Could not write architecture.svg")?;
    Ok(())
}

fn required_artifacts_exist(repo_root: &Path) -> bool {
    let artifact_dir = repo_root.join("x-ray");
    [
        REQUIRED_X_RAY_MD,
        REQUIRED_ENTRY_POINTS_MD,
        REQUIRED_INVARIANTS_MD,
        REQUIRED_ARCHITECTURE_SVG,
    ]
    .iter()
    .all(|name| artifact_dir.join(name).exists())
}

fn render_x_ray_run_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:run complete for {} ({})\n  Runtime:      {}\n  Verdict:      {}{}\n  Entry points: {}\n  Invariants:   {}\n  Cost:         ${}\n\nArtifacts:\n  - {}\n  - {}\n  - {}\n  - {}",
        data.repo_name,
        data.target,
        data.runtime_mode,
        data.verdict.tier.as_deref().unwrap_or("unknown"),
        if data.verdict.summary.is_empty() {
            String::new()
        } else {
            format!(" - {}", data.verdict.summary)
        },
        data.entry_point_counts.total,
        data.invariant_counts.total,
        format!("{:.4}", data.cost_usd),
        data.artifact_paths.x_ray,
        data.artifact_paths.entry_points,
        data.artifact_paths.invariants,
        data.artifact_paths.architecture_svg,
    )
}

fn render_x_ray_read_summary(data: &XRayReportData) -> String {
    format!(
        "x-ray:read validated artifacts for {} ({})\n  Verdict:      {}{}\n  Entry points: {}\n  Invariants:   {}",
        data.repo_name,
        data.target,
        data.verdict.tier.as_deref().unwrap_or("unknown"),
        if data.verdict.summary.is_empty() {
            String::new()
        } else {
            format!(" - {}", data.verdict.summary)
        },
        data.entry_point_counts.total,
        data.invariant_counts.total,
    )
}

fn parse_verdict(markdown: &str) -> XRayVerdict {
    let section =
        extract_heading_section(markdown, "x-ray verdict").unwrap_or_else(|| markdown.to_string());
    let tier = find_verdict_tier(&section);
    let cleaned = clean_verdict_tiers(&section);
    let summary = first_meaningful_line(&cleaned)
        .or_else(|| first_meaningful_line(markdown))
        .unwrap_or_default();
    XRayVerdict { tier, summary }
}

fn find_verdict_tier(text: &str) -> Option<String> {
    const TIERS: [&str; 7] = [
        "FORTIFIED",
        "HARDENED",
        "ADEQUATE",
        "READY",
        "WATCH",
        "FRAGILE",
        "EXPOSED",
    ];
    let normalized = text
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>();
    TIERS
        .iter()
        .find(|tier| normalized.iter().any(|token| token == **tier))
        .map(|tier| (*tier).to_string())
}

fn clean_verdict_tiers(text: &str) -> String {
    text.lines()
        .map(|line| {
            line.split_whitespace()
                .filter(|token| find_verdict_tier(token).is_none())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_meaningful_line(markdown: &str) -> Option<String> {
    markdown.lines().find_map(|line| {
        let cleaned = line
            .trim_start_matches('#')
            .trim_start_matches('>')
            .replace("**", "")
            .trim_start_matches(['-', '*', ' ', ':'])
            .trim()
            .to_string();
        (!cleaned.is_empty() && !cleaned.chars().all(|ch| "-|:".contains(ch))).then_some(cleaned)
    })
}

fn parse_entry_point_counts(markdown: &str) -> XRayEntryPointCounts {
    if let Some(counts) = parse_entry_point_summary_counts(markdown) {
        return counts;
    }

    let permissionless = count_entries_in_section(markdown, "permissionless");
    let role_gated = count_entries_in_section(markdown, "role-gated")
        + count_entries_in_section(markdown, "role gated");
    let admin_only = count_entries_in_section(markdown, "admin-only")
        + count_entries_in_section(markdown, "admin only");
    let sectional_total = permissionless + role_gated + admin_only;
    let fallback_total = count_entry_rows(markdown);
    XRayEntryPointCounts {
        permissionless,
        role_gated,
        admin_only,
        total: if sectional_total > 0 {
            sectional_total
        } else {
            fallback_total
        },
    }
}

fn parse_entry_point_summary_counts(markdown: &str) -> Option<XRayEntryPointCounts> {
    for line in markdown.lines() {
        let line = line.trim().trim_start_matches('>').trim();
        let lower = line.to_ascii_lowercase();
        if !lower.contains("entry point")
            && !lower.contains("permissionless")
            && !lower.contains("role-gated")
            && !lower.contains("role gated")
            && !lower.contains("admin-only")
            && !lower.contains("admin only")
        {
            continue;
        }

        let total = count_before_phrase(&lower, "entry point");
        let permissionless = count_before_phrase(&lower, "permissionless");
        let role_gated = count_before_phrase(&lower, "role-gated")
            .or_else(|| count_before_phrase(&lower, "role gated"));
        let admin_only = count_before_phrase(&lower, "admin-only")
            .or_else(|| count_before_phrase(&lower, "admin only"));

        if total.is_none()
            && permissionless.is_none()
            && role_gated.is_none()
            && admin_only.is_none()
        {
            continue;
        }

        let permissionless = permissionless.unwrap_or(0);
        let role_gated = role_gated.unwrap_or(0);
        let admin_only = admin_only.unwrap_or(0);
        return Some(XRayEntryPointCounts {
            permissionless,
            role_gated,
            admin_only,
            total: total.unwrap_or(permissionless + role_gated + admin_only),
        });
    }
    None
}

fn count_before_phrase(line: &str, phrase: &str) -> Option<usize> {
    let index = line.find(phrase)?;
    let prefix = line[..index].trim_end();
    let digits = prefix
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return None;
    }
    let value = digits.into_iter().rev().collect::<String>();
    value.parse().ok()
}

fn count_entries_in_section(markdown: &str, heading: &str) -> usize {
    extract_heading_section(markdown, heading)
        .map(|section| count_entry_rows(&section))
        .unwrap_or(0)
}

fn count_entry_rows(markdown: &str) -> usize {
    let heading_rows = markdown
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
            (3..=5).contains(&hashes).then(|| trimmed[hashes..].trim())
        })
        .filter(|label| {
            let lower = label.to_ascii_lowercase();
            !lower.contains("permissionless")
                && !lower.contains("role-gated")
                && !lower.contains("role gated")
                && !lower.contains("admin-only")
                && !lower.contains("admin only")
                && is_likely_entry_label(label)
        })
        .count();

    let table_rows = markdown
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("entry")
                && !lower.contains("permission")
                && !lower.contains("role")
                && !lower.contains("admin")
                && !lower.contains("---")
                && is_likely_entry_label(line.split('|').nth(1).unwrap_or_default())
        })
        .count();

    heading_rows.max(table_rows)
}

fn is_likely_entry_label(value: &str) -> bool {
    let normalized = value.replace(['`', '*', '_'], "").trim().to_string();
    normalized.contains('(')
        || normalized.contains("::")
        || normalized.contains('.')
        || normalized
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
}

fn parse_invariant_counts(markdown: &str) -> XRayInvariantCounts {
    let global = count_prefixed_tokens(markdown, 'G');
    let integration = count_prefixed_tokens(markdown, 'I');
    let cross_chain = count_prefixed_tokens(markdown, 'X');
    let economic = count_prefixed_tokens(markdown, 'E');
    let total = global + integration + cross_chain + economic;
    XRayInvariantCounts {
        global,
        integration,
        cross_chain,
        economic,
        total: if total > 0 {
            total
        } else {
            count_invariant_headings(markdown)
        },
    }
}

fn count_prefixed_tokens(text: &str, prefix: char) -> usize {
    let chars = text.chars().collect::<Vec<_>>();
    let mut out = BTreeSet::new();
    let mut index = 0usize;
    while index < chars.len() {
        if !chars[index].eq_ignore_ascii_case(&prefix) {
            index += 1;
            continue;
        }
        let previous_is_word = index > 0 && chars[index - 1].is_ascii_alphanumeric();
        if previous_is_word {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        if chars.get(cursor) == Some(&'-') {
            cursor += 1;
        }
        let start_digits = cursor;
        while chars
            .get(cursor)
            .is_some_and(|candidate| candidate.is_ascii_digit())
        {
            cursor += 1;
        }
        if cursor > start_digits {
            let digits = chars[start_digits..cursor].iter().collect::<String>();
            out.insert(format!("{}-{}", prefix.to_ascii_uppercase(), digits));
        }
        index = cursor.max(index + 1);
    }
    out.len()
}

fn count_invariant_headings(markdown: &str) -> usize {
    markdown
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            let hashes = trimmed.chars().take_while(|ch| *ch == '#').count();
            (3..=5).contains(&hashes) && trimmed.to_ascii_lowercase().contains("invariant")
        })
        .count()
}

fn extract_heading_section(markdown: &str, heading: &str) -> Option<String> {
    let lines = markdown.lines().collect::<Vec<_>>();
    let heading_lower = heading.to_ascii_lowercase();
    let start = lines.iter().position(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with('#') && trimmed.to_ascii_lowercase().contains(&heading_lower)
    })?;
    let level = lines[start]
        .chars()
        .take_while(|ch| *ch == '#')
        .count()
        .max(1);
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            let count = trimmed.chars().take_while(|ch| *ch == '#').count();
            count > 0 && count <= level && trimmed.chars().nth(count) == Some(' ')
        })
        .map(|(index, _)| index)
        .unwrap_or(lines.len());
    Some(lines[start + 1..end].join("\n"))
}

fn repo_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::runtime::{AgentQueryResponse, TriageRequest};
    use crate::{TriageOutcome, TriageVerdict, WorkspaceTarget};
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
        response: AgentQueryResponse,
    }

    impl MockRuntime {
        fn new(response: AgentQueryResponse) -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
                response,
            }
        }

        fn queries(&self) -> Vec<AgentQueryRequest> {
            self.queries.lock().unwrap().clone()
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.queries.lock().unwrap().push(request);
            Ok(self.response.clone())
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.0,
                rationale: "unused".to_string(),
            })
        }
    }

    fn write_fixture(root: &Path) {
        let dir = root.join("x-ray");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(REQUIRED_X_RAY_MD),
            "# X-Ray\n\n## X-Ray Verdict\nREADY\nThe protocol has clear core flows.\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_ENTRY_POINTS_MD),
            "# Entry Points\n\n> TinyVault | 4 entry points | 2 permissionless | 1 role-gated | 1 admin-only\n\n## Permissionless Entry Points\n### deposit(uint256 amount)\n### withdraw(uint256 shares)\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_INVARIANTS_MD),
            "# Invariants\n\n### G-1 Total assets cover shares\n### G2 No stale accounting\n### I-1 Oracle bounds\n### X-1 Bridge replay\n### E-1 Fee conservation\n",
        )
        .unwrap();
        fs::write(
            dir.join(REQUIRED_ARCHITECTURE_SVG),
            r#"<svg xmlns="http://www.w3.org/2000/svg" />"#,
        )
        .unwrap();
    }

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
        }
    }

    #[test]
    fn reads_existing_x_ray_artifacts() {
        let tmp = tempdir().unwrap();
        write_fixture(tmp.path());
        let data = read_x_ray_report_artifacts(tmp.path(), None, "rust", 0.0).unwrap();

        assert_eq!(data.verdict.tier.as_deref(), Some("READY"));
        assert_eq!(data.verdict.summary, "The protocol has clear core flows.");
        assert_eq!(data.entry_point_counts.total, 4);
        assert_eq!(data.entry_point_counts.permissionless, 2);
        assert_eq!(data.invariant_counts.global, 2);
        assert_eq!(data.invariant_counts.total, 5);
    }

    #[test]
    fn run_writes_structured_pi_agent_core_artifacts() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".to_string()),
            ..V2Config::default()
        };
        let runtime = MockRuntime::new(AgentQueryResponse {
            text: String::new(),
            structured: Some(json!({
                "xRayMarkdown": "# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n",
                "entryPointsMarkdown": "# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
                "invariantsMarkdown": "# Invariants\n\n### G-1 Balance conservation\n",
                "architectureSvg": "<svg xmlns=\"http://www.w3.org/2000/svg\" />\n",
            })),
        });

        let output = execute_x_ray_tool(
            "x-ray:run",
            json!({}),
            &context(&config, &workspace),
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(output.get("ok").and_then(Value::as_bool), Some(true));
        assert!(workspace.root().join("x-ray/x-ray.md").exists());
        assert!(output
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("x-ray:run complete"));
        assert_eq!(runtime.queries().len(), 1);
        assert_eq!(runtime.queries()[0].model, "openai:gpt-4.1");
    }

    #[test]
    fn run_requires_explicit_model_without_fallback() {
        let tmp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let config = V2Config::default();
        let runtime = MockRuntime::new(AgentQueryResponse {
            text: String::new(),
            structured: None,
        });

        let err = execute_x_ray_tool(
            "x-ray:run",
            json!({}),
            &context(&config, &workspace),
            Some(&runtime),
        )
        .unwrap_err();

        assert!(err.to_string().contains("explicit model"));
        assert!(runtime.queries().is_empty());
    }

    #[test]
    fn read_reports_missing_required_artifacts() {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("x-ray")).unwrap();
        fs::write(tmp.path().join("x-ray/x-ray.md"), "# X-Ray\n").unwrap();

        let err = read_x_ray_report_artifacts(tmp.path(), None, "rust", 0.0).unwrap_err();
        assert!(err.to_string().contains("missing required artifact"));
    }
}
