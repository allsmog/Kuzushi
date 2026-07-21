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
/// Upper bound on shard × threat × model cells materialized before the cap.
/// Real campaigns sit orders of magnitude below this; crossing it means the
/// inputs are degenerate and deserve an error, not an OOM.
const MAX_PLANNED_CELLS: usize = 100_000;

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
    /// Deliberately plan unseasoned jobs when present threat documents
    /// carry no threats[] (pack context distillations), instead of erroring.
    allow_unseasoned: bool,
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
    let documents = threat_documents(&root, request.models_dir.as_deref())?;
    let threats = planned_threats(&documents);
    ensure_documents_yield_threats(&documents, &threats, request.allow_unseasoned)?;
    ensure_plannable_cell_count(&shards, &threats, &request.models)?;
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
    let mut plan =
        plan_document(&root, &request, &jobs, &dropped, skipped_covered, threats.len())?;
    if threats.is_empty() && !documents.is_empty() {
        // allowUnseasoned bypassed the empty-document guard; the plan must
        // name the documents that steered nothing so nobody assumes seasoning.
        plan["unseasonedDocuments"] =
            json!(documents.iter().map(|(source, _)| source).collect::<Vec<_>>());
    }
    let plan_path = campaign_plan_path(&root, &request.campaign_id);
    write_json_atomic(&plan_path, &plan)?;
    Ok(plan_result(
        &request,
        &plan_path,
        jobs.len(),
        &dropped,
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
        allow_unseasoned: ["allowUnseasoned", "allow_unseasoned"]
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
        None => persistent_document(root),
    }
}

/// A missing workspace threat model legitimately plans unseasoned jobs; a
/// present-but-unloadable one must error. Swallowing that failure would
/// silently drop the entire threat axis and misrepresent the plan.
fn persistent_document(root: &Path) -> Result<Vec<(String, Value)>> {
    let document = crate::capabilities::threat_model::try_load_persistent_threat_model(root)
        .context("campaign:plan cannot season jobs; fix or remove the workspace threat model")?;
    Ok(document
        .map(|document| vec![("threat-model.json".to_string(), document)])
        .unwrap_or_default())
}

/// Threat documents that parse but contain no `threats[]` rows would
/// silently plan unseasoned jobs while the operator believes the documents
/// are steering the campaign. Name the empty documents instead.
fn ensure_documents_yield_threats(
    documents: &[(String, Value)],
    threats: &[PlannedThreat],
    allow_unseasoned: bool,
) -> Result<()> {
    if documents.is_empty() || !threats.is_empty() || allow_unseasoned {
        return Ok(());
    }
    anyhow::bail!(
        "threat document(s) {} contain no threats[]; pass allowUnseasoned=true \
         (or remove them) to plan unseasoned jobs deliberately",
        documents
            .iter()
            .map(|(source, _)| format!("{source:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn ensure_plannable_cell_count(
    shards: &[CampaignShard],
    threats: &[PlannedThreat],
    models: &[String],
) -> Result<()> {
    let cells = shards
        .len()
        .saturating_mul(threats.len().max(1))
        .saturating_mul(models.len().max(1));
    anyhow::ensure!(
        cells <= MAX_PLANNED_CELLS,
        "shards × threats × models crosses {cells} cells (limit {MAX_PLANNED_CELLS}); \
         filter shards, split modelsDir, or trim models before planning"
    );
    Ok(())
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
/// gap-filling, rank by threat weight, and keep the top `max_jobs` with a
/// breadth-first spread across shards. Both the coverage skip and every
/// capped job are reported, never silent.
fn ranked_jobs(
    shards: &[CampaignShard],
    threats: &[PlannedThreat],
    models: &[String],
    max_jobs: usize,
    covered: Option<&std::collections::BTreeSet<(String, String)>>,
) -> (Vec<PlannedJob>, Vec<PlannedJob>, usize) {
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
    // Stable sort: manifest order (shards) and declaration order (threats)
    // break priority ties deterministically.
    jobs.sort_by(|left, right| right.priority.cmp(&left.priority));
    let (kept, dropped) = breadth_first_capped(jobs, max_jobs);
    (kept, dropped, skipped_covered)
}

/// Priority-ordered round-robin over shards: each shard's jobs keep their
/// priority order, and rounds take one job per shard (shards ordered by
/// their best job) until the cap. Every shard keeps its highest-ranked jobs
/// before any shard goes deeper — so a cap under mass priority ties (e.g.
/// saturated CWE scores) degrades to even coverage instead of silently
/// truncating whole trailing shards.
fn breadth_first_capped(
    jobs: Vec<PlannedJob>,
    max_jobs: usize,
) -> (Vec<PlannedJob>, Vec<PlannedJob>) {
    let mut buckets: Vec<(String, std::collections::VecDeque<PlannedJob>)> = Vec::new();
    for job in jobs {
        match buckets.iter_mut().find(|(name, _)| *name == job.shard.name) {
            Some((_, bucket)) => bucket.push_back(job),
            None => buckets.push((job.shard.name.clone(), [job].into())),
        }
    }
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    while buckets.iter().any(|(_, bucket)| !bucket.is_empty()) {
        for (_, bucket) in &mut buckets {
            let Some(job) = bucket.pop_front() else { continue };
            if kept.len() < max_jobs {
                kept.push(job);
            } else {
                dropped.push(job);
            }
        }
    }
    (kept, dropped)
}

/// The same threat-granular cell identity `covered_cells` folds: shard ×
/// (source stem + threat id), with unseasoned jobs under the shared
/// sentinel in both positions. Matching at threat granularity means
/// fillGaps skips exactly the threats that ran — completing one threat
/// from a document never hides the document's other threats.
fn coverage_cell(job: &PlannedJob) -> (String, String) {
    let sentinel = super::coverage::UNSEASONED_COLUMN;
    let (source, threat) = job
        .threat
        .as_ref()
        .map(|threat| (threat.source.as_str(), threat.id.as_str()))
        .unwrap_or((sentinel, sentinel));
    (
        job.shard.name.clone(),
        super::coverage::threat_cell_column(source, threat),
    )
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
    dropped: &[PlannedJob],
    skipped_covered: usize,
    threat_count: usize,
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
        "threatCount": threat_count,
        "seasoned": request.season_prompts && threat_count > 0,
        "droppedJobs": dropped.len(),
        "droppedByShard": dropped_by_shard(dropped),
        "droppedTopPriority": dropped.iter().map(|job| job.priority).max(),
        "fillGaps": request.fill_gaps,
        "skippedCoveredCells": skipped_covered,
        "jobs": rows,
    }))
}

/// Which shards lost how many jobs to the cap — the identity behind the
/// `droppedJobs` count, so an operator can see whether a cut concentrated
/// on one shard or spread evenly.
fn dropped_by_shard(dropped: &[PlannedJob]) -> Value {
    let mut counts = std::collections::BTreeMap::<&str, u64>::new();
    for job in dropped {
        *counts.entry(job.shard.name.as_str()).or_default() += 1;
    }
    Value::Object(
        counts
            .into_iter()
            .map(|(shard, count)| (shard.to_string(), json!(count)))
            .collect(),
    )
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

/// Unseasoned plans are legal but must say so — an operator reading
/// "wrote 4 job(s)" would assume threat seasoning. When allowUnseasoned
/// bypassed present-but-empty documents, name them.
fn seasoning_note(plan: &Value) -> String {
    if plan.get("threatCount").and_then(Value::as_u64) != Some(0) {
        return String::new();
    }
    match plan.get("unseasonedDocuments") {
        Some(documents) => {
            format!(", unseasoned: {documents} contain no threats[] (allowUnseasoned)")
        }
        None => ", unseasoned: no threat documents".to_string(),
    }
}

fn plan_result(
    request: &PlanRequest,
    plan_path: &Path,
    job_count: usize,
    dropped: &[PlannedJob],
    skipped_covered: usize,
    plan: &Value,
) -> Value {
    let gap_note = if request.fill_gaps {
        format!(", {skipped_covered} covered cell(s) skipped by fillGaps")
    } else {
        String::new()
    };
    // Name what the cap cost: the strongest dropped priority tells the
    // operator whether the cut hit jobs as valuable as the ones kept.
    let dropped_note = match dropped.iter().map(|job| job.priority).max() {
        Some(top) => format!(
            "{} dropped by maxJobs, top dropped priority {top}",
            dropped.len()
        ),
        None => "0 dropped by maxJobs".to_string(),
    };
    let seasoning_note = seasoning_note(plan);
    let output = format!(
        "campaign:plan wrote {} job(s) ({dropped_note}{gap_note}{seasoning_note}) to {}",
        job_count,
        plan_path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "campaignId": request.campaign_id,
            "planPath": plan_path.display().to_string(),
            "jobCount": job_count,
            "droppedJobs": dropped.len(),
            "fillGaps": request.fill_gaps,
            "skippedCoveredCells": skipped_covered,
            "plan": plan,
        }),
    )
}
