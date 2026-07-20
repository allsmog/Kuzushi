//! `campaign:plan` — deterministic job-matrix generation.

use super::shards::{load_campaign_shards, CampaignShard};
use super::threats::{planned_threats, PlannedThreat};
use super::{campaign_plan_path, string_input, string_list_input, usize_input, write_json_atomic};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const DEFAULT_TOOL: &str = "sast:scan";
const DEFAULT_MAX_JOBS: usize = 64;
const DEFAULT_PROMPT_OPTION: &str = "TRIAGE_PROMPT";
const MAX_MODEL_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// Tools that take a `scopeFile` (newline-delimited repo-relative files)
/// instead of `paths`/`shard`. The planner adapts the canonical job input so
/// dispatched jobs pass descriptor validation instead of parking on an
/// unknown-option prepare failure.
const SCOPE_FILE_TOOLS: &[&str] = &["agentic-sast:scan"];

struct PlanRequest {
    campaign_id: String,
    tool: String,
    shard_filter: Vec<String>,
    models: Vec<String>,
    max_jobs: usize,
    models_dir: Option<String>,
    season_prompts: bool,
    prompt_option: String,
    /// Skip shard × threat-source cells the coverage fold already reports
    /// as completed or running, so re-planning converges on the gaps.
    fill_gaps: bool,
}

struct PlannedJob {
    shard: CampaignShard,
    threat: Option<PlannedThreat>,
    model: Option<String>,
    priority: i64,
}

pub fn execute_campaign_plan(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("campaign:plan requires an active workspace target")?;
    let root = workspace.root().to_path_buf();
    let request = parse_plan_request(input)?;
    let shards = selected_shards(&root, &request.shard_filter)?;
    let threats = planned_threats(&threat_documents(&root, request.models_dir.as_deref())?);
    let covered = request
        .fill_gaps
        .then(|| super::coverage::covered_cells(&root))
        .transpose()?;
    let (jobs, dropped, skipped_covered) = ranked_jobs(
        &shards,
        &threats,
        &request.models,
        request.max_jobs,
        covered.as_ref(),
    );
    let plan = plan_document(&root, &request, &jobs, dropped, skipped_covered)?;
    let plan_path = campaign_plan_path(&root, &request.campaign_id);
    write_json_atomic(&plan_path, &plan)?;
    Ok(plan_result(
        &request,
        &plan_path,
        jobs.len(),
        dropped,
        skipped_covered,
        &plan,
    ))
}

fn parse_plan_request(input: &Value) -> Result<PlanRequest> {
    let max_jobs = usize_input(input, &["maxJobs", "max_jobs"], DEFAULT_MAX_JOBS);
    anyhow::ensure!(max_jobs >= 1, "maxJobs must be at least 1");
    Ok(PlanRequest {
        campaign_id: campaign_id(input)?,
        tool: string_input(input, &["tool"]).unwrap_or_else(|| DEFAULT_TOOL.to_string()),
        shard_filter: string_list_input(input, &["shards"]),
        models: string_list_input(input, &["models"]),
        max_jobs,
        models_dir: string_input(input, &["modelsDir", "models_dir"]),
        season_prompts: input
            .get("seasonPrompts")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        prompt_option: string_input(input, &["promptOption", "prompt_option"])
            .unwrap_or_else(|| DEFAULT_PROMPT_OPTION.to_string()),
        fill_gaps: ["fillGaps", "fill_gaps"]
            .iter()
            .find_map(|key| input.get(key).and_then(Value::as_bool))
            .unwrap_or(false),
    })
}

fn campaign_id(input: &Value) -> Result<String> {
    let explicit = string_input(input, &["campaignId", "campaign_id", "id"]);
    let id = explicit.unwrap_or_else(generated_campaign_id);
    anyhow::ensure!(
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "campaignId {id:?} may only contain alphanumerics, '-', and '_'"
    );
    Ok(id)
}

fn generated_campaign_id() -> String {
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    format!("camp-{}", &uuid[..8])
}

fn selected_shards(root: &Path, filter: &[String]) -> Result<Vec<CampaignShard>> {
    let all = load_campaign_shards(root)?;
    if filter.is_empty() {
        return Ok(all);
    }
    let mut selected = Vec::new();
    for name in filter {
        let shard = all
            .iter()
            .find(|shard| &shard.name == name)
            .with_context(|| format!("shard {name:?} is not in the shard manifest"))?;
        selected.push(shard.clone());
    }
    Ok(selected)
}

/// Threat documents to plan over: every `*.json` in `modelsDir` (sorted by
/// file name) when given, else the persisted workspace threat model, else
/// none — an empty axis plans one un-seasoned job per shard × model.
fn threat_documents(root: &Path, models_dir: Option<&str>) -> Result<Vec<(String, Value)>> {
    match models_dir {
        Some(dir) => models_dir_documents(&resolve_models_dir(root, dir)),
        None => Ok(persistent_document(root)),
    }
}

fn persistent_document(root: &Path) -> Vec<(String, Value)> {
    crate::capabilities::threat_model::load_persistent_threat_model(root)
        .map(|document| vec![("threat-model.json".to_string(), document)])
        .unwrap_or_default()
}

fn resolve_models_dir(root: &Path, dir: &str) -> PathBuf {
    let path = Path::new(dir);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    root.join(path)
}

fn models_dir_documents(dir: &Path) -> Result<Vec<(String, Value)>> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Could not read modelsDir {}", dir.display()))?;
    let mut paths = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    anyhow::ensure!(
        !paths.is_empty(),
        "modelsDir {} contains no *.json threat model documents",
        dir.display()
    );
    paths.iter().map(|path| loaded_document(path)).collect()
}

fn loaded_document(path: &Path) -> Result<(String, Value)> {
    let body = crate::bounded_file::read_utf8_text(path, MAX_MODEL_DOCUMENT_BYTES)
        .with_context(|| format!("Could not read threat model {}", path.display()))?;
    let document = serde_json::from_str(&body)
        .with_context(|| format!("{} is malformed JSON", path.display()))?;
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());
    Ok((stem, document))
}

/// Cross shards × threats × models, drop already-covered cells when
/// gap-filling, rank by threat weight, keep the top `max_jobs`. Both the
/// coverage skip and the cap are reported, never silent.
fn ranked_jobs(
    shards: &[CampaignShard],
    threats: &[PlannedThreat],
    models: &[String],
    max_jobs: usize,
    covered: Option<&std::collections::BTreeSet<(String, String)>>,
) -> (Vec<PlannedJob>, usize, usize) {
    let mut jobs = Vec::new();
    for shard in shards {
        for threat in threat_axis(threats) {
            for model in model_axis(models) {
                jobs.push(planned_job(shard, threat, model));
            }
        }
    }
    let before = jobs.len();
    if let Some(covered) = covered {
        jobs.retain(|job| !covered.contains(&coverage_cell(job)));
    }
    let skipped_covered = before - jobs.len();
    jobs.sort_by(|left, right| right.priority.cmp(&left.priority));
    let dropped = jobs.len().saturating_sub(max_jobs);
    jobs.truncate(max_jobs);
    (jobs, dropped, skipped_covered)
}

/// The same cell identity the coverage matrix folds: shard name × threat
/// source stem, with unseasoned jobs under the shared sentinel column.
fn coverage_cell(job: &PlannedJob) -> (String, String) {
    let source = job
        .threat
        .as_ref()
        .map(|threat| threat.source.clone())
        .unwrap_or_else(|| super::coverage::UNSEASONED_COLUMN.to_string());
    (job.shard.name.clone(), source)
}

fn threat_axis(threats: &[PlannedThreat]) -> Vec<Option<&PlannedThreat>> {
    if threats.is_empty() {
        return vec![None];
    }
    threats.iter().map(Some).collect()
}

fn model_axis(models: &[String]) -> Vec<Option<&String>> {
    if models.is_empty() {
        return vec![None];
    }
    models.iter().map(Some).collect()
}

fn planned_job(
    shard: &CampaignShard,
    threat: Option<&PlannedThreat>,
    model: Option<&String>,
) -> PlannedJob {
    PlannedJob {
        shard: shard.clone(),
        threat: threat.cloned(),
        model: model.cloned(),
        priority: threat.map(threat_priority).unwrap_or(15),
    }
}

/// Deterministic rank: declared severity dominates, CWE specificity breaks
/// ties (more related CWEs = more scanner-actionable focus).
fn threat_priority(threat: &PlannedThreat) -> i64 {
    let severity = match threat.severity.as_str() {
        "critical" | "p0" => 40,
        "high" | "p1" => 30,
        "medium" | "p2" => 20,
        "low" | "p3" => 10,
        _ => 15,
    };
    severity + (threat.cwes.len() as i64 * 5).min(25)
}

fn plan_document(
    root: &Path,
    request: &PlanRequest,
    jobs: &[PlannedJob],
    dropped: usize,
    skipped_covered: usize,
) -> Result<Value> {
    let mut rows = Vec::new();
    let mut scope_files = std::collections::HashMap::new();
    for (index, job) in jobs.iter().enumerate() {
        let job_id = format!("job-{:03}", index + 1);
        let prompt_path = seasoned_prompt_path(root, request, &job_id, job)?;
        let scope_path = job_scope_file(root, request, job, &mut scope_files)?;
        rows.push(job_row(request, &job_id, job, prompt_path, scope_path));
    }
    Ok(json!({
        "campaignId": request.campaign_id,
        "tool": request.tool,
        "createdAtMs": epoch_ms(),
        "axes": {
            "shards": jobs_axis_names(jobs),
            "models": request.models,
            "promptOption": request.prompt_option,
        },
        "jobCount": rows.len(),
        "droppedJobs": dropped,
        "fillGaps": request.fill_gaps,
        "skippedCoveredCells": skipped_covered,
        "jobs": rows,
    }))
}

fn jobs_axis_names(jobs: &[PlannedJob]) -> Vec<String> {
    let mut names = jobs.iter().map(|job| job.shard.name.clone()).collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn job_row(
    request: &PlanRequest,
    job_id: &str,
    job: &PlannedJob,
    prompt_path: Option<String>,
    scope_path: Option<String>,
) -> Value {
    let input = job_input(request, job, prompt_path.as_deref(), scope_path.as_deref());
    json!({
        "jobId": job_id,
        "tool": request.tool,
        "shard": job.shard.name,
        "paths": job.shard.paths,
        "threatId": job.threat.as_ref().map(|threat| threat.id.clone()),
        "threatTitle": job.threat.as_ref().map(|threat| threat.title.clone()),
        "threatSource": job.threat.as_ref().map(|threat| threat.source.clone()),
        "cwes": job.threat.as_ref().map(|threat| threat.cwes.clone()).unwrap_or_default(),
        "severity": job.threat.as_ref().map(|threat| threat.severity.clone()),
        "model": job.model,
        "promptPath": prompt_path,
        "priority": job.priority,
        "state": "planned",
        "input": input,
    })
}

/// The canonical tool input the dispatcher passes to `kuzushi run` verbatim.
/// Scope-file tools get `scopeFile` instead of `paths`/`shard`, which they
/// would reject as unknown options.
fn job_input(
    request: &PlanRequest,
    job: &PlannedJob,
    prompt_path: Option<&str>,
    scope_path: Option<&str>,
) -> Value {
    let mut input = serde_json::Map::new();
    match scope_path {
        Some(scope) => {
            input.insert("scopeFile".to_string(), json!(scope));
        }
        None if !job.shard.paths.is_empty() => {
            input.insert("paths".to_string(), json!(job.shard.paths));
            input.insert("shard".to_string(), json!(job.shard.name));
        }
        None => {}
    }
    if let Some(model) = &job.model {
        input.insert("model".to_string(), json!(model));
    }
    if let Some(path) = prompt_path {
        input.insert(request.prompt_option.clone(), json!(path));
    }
    Value::Object(input)
}

/// For scope-file tools, materialize the shard's file list once per shard
/// under the campaign directory and reuse it across that shard's jobs.
fn job_scope_file(
    root: &Path,
    request: &PlanRequest,
    job: &PlannedJob,
    cache: &mut std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    if !SCOPE_FILE_TOOLS.contains(&request.tool.as_str()) || job.shard.paths.is_empty() {
        return Ok(None);
    }
    if let Some(existing) = cache.get(&job.shard.name) {
        return Ok(Some(existing.clone()));
    }
    let relative = format!(
        ".kuzushi/v3/campaigns/{}/scope/{}.txt",
        request.campaign_id, job.shard.name
    );
    write_shard_scope_file(root, &relative, &job.shard)?;
    cache.insert(job.shard.name.clone(), relative.clone());
    Ok(Some(relative))
}

fn write_shard_scope_file(root: &Path, relative: &str, shard: &CampaignShard) -> Result<()> {
    let mut files = Vec::new();
    for shard_path in &shard.paths {
        collect_scope_files(root, Path::new(shard_path), &mut files)?;
    }
    anyhow::ensure!(
        !files.is_empty(),
        "shard {:?} matched no files under {:?}; fix the shard manifest before planning scope-file tools",
        shard.name,
        shard.paths
    );
    files.sort();
    files.dedup();
    let path = root.join(relative);
    let parent = path.parent().context("scope path has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    std::fs::write(&path, files.join("\n") + "\n")
        .with_context(|| format!("Could not write {}", path.display()))
}

fn collect_scope_files(root: &Path, relative: &Path, out: &mut Vec<String>) -> Result<()> {
    let absolute = root.join(relative);
    if absolute.is_file() {
        out.push(relative.to_string_lossy().into_owned());
        return Ok(());
    }
    let Ok(entries) = std::fs::read_dir(&absolute) else {
        return Ok(()); // missing entries surface via the empty-scope check
    };
    let mut children: Vec<_> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| !name.to_string_lossy().starts_with('.'))
        .collect();
    children.sort();
    for child in children {
        collect_scope_files(root, &relative.join(child), out)?;
    }
    Ok(())
}

/// Write the seasoning prompt for a threat-scoped job and return its
/// workspace-relative path. The file is the FULL triage prompt (default
/// text + campaign focus): `TRIAGE_PROMPT` replaces the default wholesale,
/// so a focus-only fragment would silently drop the baseline instructions.
fn seasoned_prompt_path(
    root: &Path,
    request: &PlanRequest,
    job_id: &str,
    job: &PlannedJob,
) -> Result<Option<String>> {
    let (true, Some(threat)) = (request.season_prompts, job.threat.as_ref()) else {
        return Ok(None);
    };
    let relative = format!(
        ".kuzushi/prompts/campaign/{}/{job_id}.md",
        request.campaign_id
    );
    let path = root.join(&relative);
    let parent = path.parent().context("prompt path has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    std::fs::write(&path, seasoned_prompt_body(root, request, threat))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(Some(relative))
}

/// Passing a prompt option explicitly bypasses the
/// `.kuzushi/prompts/<module>/<verb>.md` auto-load, so campaign jobs would
/// silently drop any calibration fragment installed in the workspace. The
/// seasoning file therefore carries that fragment itself. For the sast:scan
/// umbrella the triage stage reads `<module>/triage.md`, so that spelling is
/// the fallback candidate.
fn workspace_prompt_fragment(root: &Path, tool: &str, prompt_option: &str) -> Option<String> {
    let (module, verb) = tool.split_once(':')?;
    let mut candidates = vec![format!("{module}/{verb}.md")];
    if prompt_option == DEFAULT_PROMPT_OPTION {
        candidates.push(format!("{module}/triage.md"));
    }
    candidates.iter().find_map(|candidate| {
        std::fs::read_to_string(root.join(".kuzushi/prompts").join(candidate)).ok()
    })
}

/// `TRIAGE_PROMPT` replaces the default wholesale, so its seasoning must
/// carry the full baseline text. Every other prompt option resolves a path
/// value by composing it with the tool's builtin prompt, so those seasonings
/// stay focus-only fragments — duplicating a baseline there would append a
/// second, conflicting instruction set.
fn seasoned_prompt_body(root: &Path, request: &PlanRequest, threat: &PlannedThreat) -> String {
    let mut body = if request.prompt_option == DEFAULT_PROMPT_OPTION {
        format!("{}\n\n", crate::runtime::DEFAULT_TRIAGE_PROMPT)
    } else {
        String::new()
    };
    if let Some(fragment) = workspace_prompt_fragment(root, &request.tool, &request.prompt_option) {
        body.push_str(fragment.trim_end());
        body.push_str("\n\n");
    }
    body.push_str("## Campaign focus\n\n");
    body.push_str(&format!(
        "This pass targets threat {} — {}.\n",
        threat.id, threat.title
    ));
    if !threat.description.is_empty() {
        body.push_str(&format!("\n{}\n", threat.description));
    }
    if !threat.cwes.is_empty() {
        body.push_str(&format!(
            "\nPrioritize findings matching: {}.\n",
            threat.cwes.join(", ")
        ));
    }
    body.push_str("\nOther true positives must still be kept; this focus reorders attention, it does not filter findings.\n");
    body
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn plan_result(
    request: &PlanRequest,
    plan_path: &Path,
    job_count: usize,
    dropped: usize,
    skipped_covered: usize,
    plan: &Value,
) -> Value {
    let gap_note = if request.fill_gaps {
        format!(", {skipped_covered} covered cell(s) skipped by fillGaps")
    } else {
        String::new()
    };
    let output = format!(
        "campaign:plan wrote {} job(s) ({} dropped by maxJobs{gap_note}) to {}",
        job_count,
        dropped,
        plan_path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "campaignId": request.campaign_id,
            "planPath": plan_path.display().to_string(),
            "jobCount": job_count,
            "droppedJobs": dropped,
            "fillGaps": request.fill_gaps,
            "skippedCoveredCells": skipped_covered,
            "plan": plan,
        }),
    )
}
