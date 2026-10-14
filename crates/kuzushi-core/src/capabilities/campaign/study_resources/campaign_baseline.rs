//! Read one explicitly named finite study. Never discover jobs or query a model.
use super::campaign_preview::{CaseResourceEvidenceV1, StudyResourceEvidenceV1};
use super::catalogue::load_named_scan_usage;
use crate::capabilities::campaign::{self, FrozenContextCase};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{Number, Value};
use std::path::Path;

const METADATA_BYTES: usize = 1024 * 1024;
const PREVIEW_BYTES: usize = 32 * METADATA_BYTES;

pub(in crate::capabilities::campaign) fn attach(
    ctx: &ToolExecutionContext<'_>,
    input: &Value,
    cases: &[FrozenContextCase],
    plan: &mut Value,
) -> Result<()> {
    let Some(id) = selected_baseline(input, plan)? else {
        return Ok(());
    };
    let root = ctx
        .workspace
        .context("Resource preview requires a workspace")?
        .root();
    let baseline = campaign::approved_work::read_bounded_plan(root, id)?;
    validate_baseline(id, &baseline)?;
    let queue = bounded_queue(root, id)?;
    let mut reader = BaselineRunReader {
        root,
        id,
        queue: &queue,
        remaining: PREVIEW_BYTES,
        ctx,
    };
    let previews = cases
        .iter()
        .map(|case| reader.case_evidence(case, &baseline))
        .collect::<Result<Vec<_>>>()?;
    let evidence = StudyResourceEvidenceV1 {
        schema_version: 1,
        baseline_campaign_id: id.into(),
        baseline_plan_sha256: campaign::batch::equivalence::digest_serializable(&baseline)?,
        cases: previews,
    };
    evidence.project(1)?;
    plan["resourceEvidence"] = serde_json::to_value(evidence)?;
    Ok(())
}

fn selected_baseline<'a>(input: &'a Value, plan: &Value) -> Result<Option<&'a str>> {
    let Some(value) = input.get("resourceBaselineCampaignId") else {
        return Ok(None);
    };
    let id = value
        .as_str()
        .context("resourceBaselineCampaignId must be a string")?;
    campaign::validate_scan_batch_id(id)?;
    anyhow::ensure!(
        input.get("baselineRunId").is_none(),
        "Choose one usage run or one prior study"
    );
    anyhow::ensure!(
        plan["campaignId"].as_str() != Some(id),
        "A study cannot calibrate itself"
    );
    Ok(Some(id))
}

struct BaselineRunReader<'a, 'ctx> {
    root: &'a Path,
    id: &'a str,
    queue: &'a Value,
    remaining: usize,
    ctx: &'a ToolExecutionContext<'ctx>,
}

fn validate_baseline(id: &str, plan: &Value) -> Result<()> {
    match plan["kind"].as_str() {
        Some(campaign::SCOPE_STUDY_KIND) => {
            campaign::validate_scope_study_plan(id, plan)?;
        }
        Some(campaign::CONTEXT_MATRIX_KIND) => {
            campaign::validate_context_matrix_plan(id, plan)?;
        }
        _ => anyhow::bail!("Usage baseline requires a prior scope study or context matrix"),
    }
    Ok(())
}

fn bounded_queue(root: &Path, id: &str) -> Result<Value> {
    let path = campaign::campaign_queue_path(root, id);
    if !path.exists() {
        return Ok(Value::Null);
    }
    let text = crate::bounded_file::read_utf8_text_within(root, &path, METADATA_BYTES)?;
    let queue: Value = serde_json::from_str(&text)?;
    anyhow::ensure!(
        queue["jobs"]
            .as_object()
            .is_some_and(|jobs| jobs.len() <= 100),
        "Invalid prior study queue"
    );
    Ok(queue)
}

impl BaselineRunReader<'_, '_> {
    fn case_evidence(
        &mut self,
        case: &FrozenContextCase,
        plan: &Value,
    ) -> Result<CaseResourceEvidenceV1> {
        let mut result = CaseResourceEvidenceV1 {
            case_id: case.id.clone(),
            equivalence_sha256: case.equivalence.sha256.clone(),
            passes: case.passes,
            run_ids: Vec::new(),
            calls_per_pass: None,
            cost_per_pass_usd: None,
            limitations: Vec::new(),
        };
        let mut observations = Vec::new();
        for job in plan["jobs"]
            .as_array()
            .context("Prior study jobs missing")?
        {
            require_active(self.ctx)?;
            self.read_job(case, job, &mut result, &mut observations);
        }
        apply_observations(&mut result, &observations);
        if observations.is_empty() {
            result.limitations.push("No complete matching passes; recorded conditions may differ or the selected study may lack completed work".into());
        }
        Ok(result)
    }

    fn read_job(
        &mut self,
        case: &FrozenContextCase,
        job: &Value,
        result: &mut CaseResourceEvidenceV1,
        observations: &mut Vec<(Option<u32>, Option<f64>)>,
    ) {
        let Some(run) = matching_run(job, self.queue, case) else {
            return;
        };
        if result.run_ids.iter().any(|id| id == run) {
            result
                .limitations
                .push(format!("{run}: duplicate run reference ignored"));
            return;
        }
        match observation(self.root, self.id, run, case, &mut self.remaining) {
            Ok(value) => {
                result.run_ids.push(run.into());
                observations.push(value);
            }
            Err(error) => result.limitations.push(format!("{run}: {error:#}")),
        }
    }
}

fn matching_run<'a>(job: &Value, queue: &'a Value, case: &FrozenContextCase) -> Option<&'a str> {
    if job["input"]["batchEquivalenceKey"].as_str()? != case.equivalence.sha256 {
        return None;
    }
    let state = queue["jobs"].get(job["jobId"].as_str()?)?;
    (state["state"] == "completed").then_some(())?;
    state["runId"].as_str()
}

fn observation(
    root: &Path,
    id: &str,
    run: &str,
    case: &FrozenContextCase,
    remaining: &mut usize,
) -> Result<(Option<u32>, Option<f64>)> {
    reserve_metadata(root, run, remaining)?;
    let child = campaign::load_scan_batch_child_equivalence_receipt(root, run)?;
    anyhow::ensure!(
        child.batch_id == id,
        "Usage run belongs to a different study"
    );
    let evidence = load_named_scan_usage(root, run)?;
    let projected = evidence.project(&case.equivalence, 1, 1)?;
    Ok((
        projected.provider_calls.map(|calls| calls as u32),
        projected.cost_usd,
    ))
}

fn reserve_metadata(root: &Path, run: &str, remaining: &mut usize) -> Result<()> {
    for name in [
        "run.json",
        campaign::SCAN_BATCH_EQUIVALENCE_RECEIPT_FILE,
        "phase-stages.jsonl",
    ] {
        let path = crate::run_artifacts::resolve_run_artifact_path(root, run, name)?;
        let text = crate::bounded_file::read_utf8_text_within(
            root,
            &path,
            (*remaining).min(METADATA_BYTES),
        )?;
        *remaining = remaining
            .checked_sub(text.len())
            .context("Resource preview metadata budget exhausted")?;
    }
    Ok(())
}

fn apply_observations(
    result: &mut CaseResourceEvidenceV1,
    observations: &[(Option<u32>, Option<f64>)],
) {
    let calls = observations
        .iter()
        .map(|value| value.0)
        .collect::<Option<Vec<_>>>();
    result.calls_per_pass =
        calls.and_then(|values| Some([*values.iter().min()?, *values.iter().max()?]));
    let costs = observations
        .iter()
        .map(|value| value.1)
        .collect::<Option<Vec<_>>>();
    result.cost_per_pass_usd = costs.and_then(|values| {
        let min = values.iter().min_by(|a, b| a.total_cmp(b))?;
        let max = values.iter().max_by(|a, b| a.total_cmp(b))?;
        Some([Number::from_f64(*min)?, Number::from_f64(*max)?])
    });
}

fn require_active(ctx: &ToolExecutionContext<'_>) -> Result<()> {
    anyhow::ensure!(
        !ctx.cancellation.is_some_and(|value| value.is_cancelled()),
        "Resource preview canceled"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
