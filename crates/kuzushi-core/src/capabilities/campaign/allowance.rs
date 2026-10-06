use crate::allowance::{AllowanceApprovalV1, AllowanceLimits, AllowanceSnapshot};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalInput {
    investigation_id: String,
    expected_revision: u32,
    model: String,
    max_provider_calls: u32,
    protected_review_calls: u32,
    reason: String,
}

impl From<ApprovalInput> for AllowanceApprovalV1 {
    fn from(input: ApprovalInput) -> Self {
        Self {
            schema_version: 1,
            investigation_id: input.investigation_id,
            expected_revision: input.expected_revision,
            model: input.model,
            limits: AllowanceLimits {
                max_provider_calls: input.max_provider_calls,
                protected_review_calls: input.protected_review_calls,
            },
            reason: input.reason,
            work_plan: None,
        }
    }
}

pub fn execute_approve_allowance(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let work_plan = super::approved_work::approve_work(input, ctx)?;
    let mut fields = input.clone();
    if let Some(object) = fields.as_object_mut() {
        for key in [
            "campaignId",
            "campaignPlanSha256",
            "campaignJobs",
            "maxJobAttempts",
        ] {
            object.remove(key);
        }
    }
    let input: ApprovalInput = serde_json::from_value(fields)?;
    let mut approval: AllowanceApprovalV1 = input.into();
    approval.work_plan = work_plan;
    let ledger = open_ledger(ctx)?;
    let snapshot = ledger.approve_allowance(&approval)?;
    Ok(result(snapshot, "Allowance approved; no jobs started"))
}

pub fn execute_allowance_status(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let id = input
        .get("investigationId")
        .and_then(Value::as_str)
        .context("investigationId is required")?;
    let workspace = ctx
        .workspace
        .context("allowance requires an active workspace")?;
    let snapshot = crate::SpendLimiter::read_allowance_snapshot(&workspace.findings_db_path(), id)?;
    let mut output = result(snapshot, "Investigation allowance");
    append_run_usage(input, id, &workspace.findings_db_path(), &mut output)?;
    Ok(output)
}

fn append_run_usage(
    input: &Value,
    id: &str,
    db: &std::path::Path,
    output: &mut Value,
) -> Result<()> {
    let Some(run) = input["runId"].as_str() else {
        return Ok(());
    };
    let usage = crate::SpendLimiter::read_run_provider_usage(db, run)?;
    if let Some(usage) = &usage {
        anyhow::ensure!(
            usage.investigation_id == id,
            "run belongs to another investigation"
        );
    }
    let text = usage.as_ref().map_or_else(
        || format!("\nRun {run}: provider-request evidence unavailable; unknown is not zero."),
        |usage| format!("\nRun {run}: {} provider requests committed · {} unresolved. Includes internal turns and retries; no future usage or dollar ceiling is implied.", usage.committed_calls, usage.unresolved_calls),
    );
    for field in ["output", "summary"] {
        output[field] = Value::String(format!(
            "{}{text}",
            output[field].as_str().unwrap_or_default()
        ));
    }
    output["data"]["runUsage"] = serde_json::to_value(usage)?;
    Ok(())
}

fn open_ledger(ctx: &ToolExecutionContext<'_>) -> Result<crate::SpendLimiter> {
    let workspace = ctx
        .workspace
        .context("allowance requires an active workspace")?;
    crate::SpendLimiter::open(workspace.findings_db_path())
}

fn result(snapshot: AllowanceSnapshot, title: &str) -> Value {
    let mut summary = format!(
        "{title}: {} revision {} · {}\nCalls committed: {}/{} · remaining: {} · protected review remaining: {}\nUnresolved calls: {} · dollar ceiling: not enforced\nDollar charges may be unavailable. Calls include internal turns and retries. Approve any additional work separately.",
        snapshot.investigation_id, snapshot.revision, snapshot.model,
        snapshot.committed_calls, snapshot.limits.max_provider_calls, snapshot.remaining_calls(),
        snapshot.protected_review_remaining(), snapshot.unresolved_calls,
    );
    if let Some(plan) = &snapshot.work_plan {
        summary.push_str(&format!("\nApproved campaign: {} · {} fixed jobs\nPlan digest: {}\nSource identity: {}\nStarted attempts stay consumed after failure, cancellation and restart.", plan.campaign_id, plan.jobs.len(), plan.plan_sha256, plan.source_identity));
        for job in &plan.jobs {
            summary.push_str(&format!(
                "\n{} · {} · at most {} attempt(s)",
                job.work_id, job.tool, job.max_attempts
            ));
        }
    }
    json!({"ok":true, "output":summary, "summary":summary, "data":{"allowance":snapshot, "dollarCeilingEnforced":false}})
}
