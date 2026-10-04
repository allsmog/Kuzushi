//! Explicit deterministic Map work preceding the context draft.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextPreparationJob {
    pub tool: String,
    pub input: Value,
}

pub(super) fn prepare_jobs(
    value: Option<&Value>,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<Vec<ContextPreparationJob>> {
    let jobs: Vec<ContextPreparationJob> = value
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("preparationJobs must contain tool/input objects")?
        .unwrap_or_default();
    validate_jobs(&jobs)?;
    jobs.into_iter()
        .map(|job| prepare_job(job, ctx, registry))
        .collect()
}

fn prepare_job(
    job: ContextPreparationJob,
    ctx: &ToolExecutionContext<'_>,
    registry: &ModuleRegistry,
) -> Result<ContextPreparationJob> {
    let prepared = registry.prepare_dispatch_input(&job.tool, job.input, ctx, None)?;
    anyhow::ensure!(
        !registry.tool_wants_runtime(&job.tool, prepared.value(), ctx.config),
        "context preparation must be deterministic"
    );
    let input = prepared.value().clone();
    let root = ctx
        .workspace
        .context("context study requires a workspace")?
        .root();
    let target = input
        .get("target")
        .and_then(Value::as_str)
        .map(Path::new)
        .unwrap_or(root);
    anyhow::ensure!(
        std::fs::canonicalize(target)? == std::fs::canonicalize(root)?,
        "preparation must use its investigation repository"
    );
    Ok(ContextPreparationJob {
        tool: job.tool,
        input,
    })
}

pub(super) fn validate_jobs(jobs: &[ContextPreparationJob]) -> Result<()> {
    anyhow::ensure!(
        jobs.len() <= 2,
        "context study supports at most two preparation jobs"
    );
    let mut tools = std::collections::BTreeSet::new();
    for job in jobs {
        anyhow::ensure!(
            matches!(job.tool.as_str(), "context:build" | "entry-points:extract"),
            "{} has no supported context-study preparation contract",
            job.tool
        );
        anyhow::ensure!(
            tools.insert(&job.tool),
            "duplicate context preparation tool"
        );
        anyhow::ensure!(
            job.input.get("allowanceRef").is_none(),
            "preparation cannot supply its own allowance"
        );
    }
    Ok(())
}

pub(super) fn plan_jobs(input: Value, preparation: &[ContextPreparationJob]) -> Vec<Value> {
    let mut jobs = preparation.iter().enumerate().map(|(index, job)| {
        json!({"jobId":format!("prepare-{:03}", index + 1),"tool":job.tool,"input":job.input})
    }).collect::<Vec<_>>();
    jobs.push(json!({"jobId":JOB,"tool":TOOL,"input":input}));
    jobs
}

pub(super) fn read_jobs(jobs: &[Value]) -> Result<Vec<ContextPreparationJob>> {
    let mut preparation = Vec::new();
    for (index, job) in jobs.iter().enumerate() {
        anyhow::ensure!(
            job["jobId"] == format!("prepare-{:03}", index + 1),
            "context preparation job identity changed"
        );
        preparation.push(ContextPreparationJob {
            tool: required_text(job, "tool")?,
            input: job["input"].clone(),
        });
    }
    validate_jobs(&preparation)?;
    Ok(preparation)
}

pub(super) fn approved_jobs(receipt: &ContextStudyReceipt) -> Result<Vec<ApprovedWorkItem>> {
    plan_jobs(receipt.input.clone(), &receipt.preparation_jobs)
        .into_iter()
        .map(|job| {
            Ok(ApprovedWorkItem {
                work_id: format!("{}:{}", receipt.campaign_id, required_text(&job, "jobId")?),
                tool: required_text(&job, "tool")?,
                input_sha256: work_input_digest(&job["input"])?,
                max_attempts: 1,
            })
        })
        .collect()
}
