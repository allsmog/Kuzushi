use super::*;
use kuzushi_core::{allowance::AllowanceReferenceV1, SpendLimiter, WorkspaceTarget};

pub(super) fn bind_approved_work(
    target: &Path,
    campaign: &str,
    plan: &Value,
    jobs: &mut [PlanJob],
) -> Result<()> {
    let workspace = WorkspaceTarget::new(target)?;
    let Some(allowance) =
        SpendLimiter::read_campaign_allowance(&workspace.findings_db_path(), campaign)?
    else {
        anyhow::ensure!(
            plan.get("requiresWorkApproval") != Some(&Value::Bool(true)),
            "study requires approval of its exact jobs and allowance before execution"
        );
        return Ok(());
    };
    let approved = allowance
        .work_plan
        .as_ref()
        .context("missing approved campaign work")?;
    let actual = kuzushi_core::run_lifecycle::sha256_content_digest(
        &kuzushi_core::review_yield::domain::canonical_json_bytes(plan)?,
    );
    anyhow::ensure!(
        actual == approved.plan_sha256,
        "campaign plan differs from its operator approval"
    );
    anyhow::ensure!(
        approved.jobs.len() == jobs.len(),
        "approved campaign cannot add or omit jobs"
    );
    for job in jobs {
        bind_job(job, campaign, approved, &allowance)?;
    }
    Ok(())
}

fn bind_job(
    job: &mut PlanJob,
    campaign: &str,
    approved: &kuzushi_core::allowance::ApprovedWorkPlanV1,
    allowance: &kuzushi_core::allowance::AllowanceSnapshot,
) -> Result<()> {
    let work_id = format!("{campaign}:{}", job.job_id);
    let approved_job = approved.job(&work_id)?;
    anyhow::ensure!(
        job.tool == approved_job.tool,
        "approved campaign tool changed"
    );
    let mut input: Value = serde_json::from_str(&job.input_json)?;
    input["allowanceRef"] = serde_json::to_value(AllowanceReferenceV1 {
        schema_version: 1,
        investigation_id: allowance.investigation_id.clone(),
        revision: allowance.revision,
        work_id,
    })?;
    job.input_json = serde_json::to_string(&input)?;
    job.approved_attempts = Some(approved_job.max_attempts);
    Ok(())
}

/// Unknown prices may continue only when every job has an authenticated call
/// allowance and no dollar ceiling depends on those prices. Shared prepared
/// dispatch still reserves every provider request, including unresolved calls.
pub(super) fn call_allowance_covers_unpriced_work(
    jobs: &[PlanJob],
    settings: &DispatchSettings,
) -> bool {
    if settings.budget_usd.is_some() || settings.job_budget_usd.is_some() {
        return false;
    }
    !jobs.is_empty() && jobs.iter().all(call_limited_job)
}

fn call_limited_job(job: &PlanJob) -> bool {
    job.approved_attempts.is_some() && job.job_budget_usd.is_none()
}

/// Bound campaign attempts include quota failures. The legacy retry policy is
/// retained for campaigns that have no finite work approval.
pub(super) fn job_transition(
    job: Option<&PlanJob>,
    outcome: JobOutcome,
    rate_limited: bool,
    used: u32,
    settings: &DispatchSettings,
) -> Transition {
    let approved = job.and_then(|job| job.approved_attempts);
    transition_for(
        outcome,
        rate_limited && approved.is_none(),
        used,
        approved.unwrap_or(settings.max_attempts),
        settings.retry_backoff_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config};
    use serde_json::json;

    #[test]
    fn unknown_prices_require_every_job_to_have_a_finite_call_allowance() {
        let settings = standard_batch_dispatch_settings(1).unwrap();
        let mut job = plan_job_row(&json!({"jobId":"one","tool":"sast:scan","input":{}})).unwrap();
        assert!(!call_allowance_covers_unpriced_work(&[], &settings));
        assert!(!call_allowance_covers_unpriced_work(
            &[job.clone()],
            &settings
        ));
        let unbound = job.clone();
        job.approved_attempts = Some(1);
        assert!(call_allowance_covers_unpriced_work(
            &[job.clone()],
            &settings
        ));
        assert!(!call_allowance_covers_unpriced_work(
            &[job, unbound],
            &settings
        ));
    }

    #[test]
    fn a_dollar_ceiling_always_requires_pricing_even_for_call_bound_jobs() {
        let mut settings = standard_batch_dispatch_settings(1).unwrap();
        let mut job = plan_job_row(&json!({"jobId":"one","tool":"sast:scan","input":{}})).unwrap();
        job.approved_attempts = Some(1);
        settings.budget_usd = Some(1.0);
        assert!(!call_allowance_covers_unpriced_work(
            &[job.clone()],
            &settings
        ));
        settings.budget_usd = None;
        settings.job_budget_usd = Some(1.0);
        assert!(!call_allowance_covers_unpriced_work(
            &[job.clone()],
            &settings
        ));
        settings.job_budget_usd = None;
        job.job_budget_usd = Some(1.0);
        assert!(!call_allowance_covers_unpriced_work(&[job], &settings));
    }

    #[test]
    fn dispatcher_refuses_unapproved_study_then_binds_every_frozen_job() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let draft = registry
            .execute_tool(
                "campaign:study",
                json!({"campaignId":"finite",
            "scanInput":{"taskMode":"manual","tasks":["secret-scan"]}}),
                &ctx,
            )
            .unwrap();
        assert!(load_plan_jobs(root.path(), "finite", &[]).is_err());
        let approval = json!({"investigationId":"study","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":9,"protectedReviewCalls":3,"reason":"Offline dispatcher test",
            "campaignId":"finite","campaignJobs":3,"maxJobAttempts":1,"campaignPlanSha256":draft["data"]["planSha256"]});
        let prepared = registry
            .prepare_dispatch_input("campaign:approve-allowance", approval, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        let loaded = load_plan_jobs(root.path(), "finite", &[]).unwrap();
        assert_eq!(loaded.jobs.len(), 3);
        for job in loaded.jobs {
            let input: Value = serde_json::from_str(&job.input_json).unwrap();
            assert_eq!(
                input["allowanceRef"]["workId"],
                format!("finite:{}", job.job_id)
            );
            assert_eq!(job.approved_attempts, Some(1));
        }
        assert!(load_plan_jobs(root.path(), "finite", &["trial-001".into()]).is_err());
        let path = campaign_dir(root.path(), "finite").join("plan.json");
        let mut plan: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        plan["createdAtMs"] = json!(0);
        std::fs::write(path, serde_json::to_vec(&plan).unwrap()).unwrap();
        assert!(load_plan_jobs(root.path(), "finite", &[]).is_err());
    }

    #[test]
    fn context_study_binds_preparation_and_refuses_worker_expansion() {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let config = V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let draft = registry.execute_tool("campaign:context-study", json!({
            "campaignId":"map-context","investigationId":"map-investigation","contextInput":{},
            "preparationJobs":[{"tool":"context:build","input":{}},{"tool":"entry-points:extract","input":{}}]
        }), &ctx).unwrap();
        assert!(load_plan_jobs(root.path(), "map-context", &[]).is_err());
        let terms = json!({"investigationId":"map-investigation","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":5,"protectedReviewCalls":2,"reason":"Offline Setup context test",
            "campaignId":"map-context","campaignJobs":3,"maxJobAttempts":1,"campaignPlanSha256":draft["data"]["planSha256"]});
        let prepared = registry
            .prepare_dispatch_input("campaign:approve-allowance", terms, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        let loaded = load_plan_jobs(root.path(), "map-context", &[]).unwrap();
        assert_eq!(
            loaded
                .jobs
                .iter()
                .map(|job| job.tool.as_str())
                .collect::<Vec<_>>(),
            [
                "context:build",
                "entry-points:extract",
                "threat-model:build"
            ]
        );
        let mut settings = standard_batch_dispatch_settings(1).unwrap();
        assert!(enforce_scan_batch_worker_boundary(&loaded, &settings).is_ok());
        settings.workers = 2;
        assert!(enforce_scan_batch_worker_boundary(&loaded, &settings).is_err());
        assert!(load_plan_jobs(root.path(), "map-context", &["context-001".into()]).is_err());
        for job in loaded.jobs {
            let input: Value = serde_json::from_str(&job.input_json).unwrap();
            assert_eq!(
                input["allowanceRef"]["workId"],
                format!("map-context:{}", job.job_id)
            );
            assert_eq!(job.approved_attempts, Some(1));
        }
    }

    #[test]
    fn quota_failures_consume_finite_attempts_instead_of_retrying_forever() {
        let settings = standard_batch_dispatch_settings(1).unwrap();
        let mut job = plan_job_row(&json!({"jobId":"one","tool":"sast:scan","input":{}})).unwrap();
        job.approved_attempts = Some(1);
        assert_eq!(
            job_transition(Some(&job), JobOutcome::ToolFailed, true, 1, &settings),
            Transition::Fail
        );
        job.approved_attempts = Some(2);
        assert!(matches!(
            job_transition(Some(&job), JobOutcome::ToolFailed, true, 1, &settings),
            Transition::Requeue {
                consume_attempt: true,
                ..
            }
        ));
        job.approved_attempts = None;
        assert!(matches!(
            job_transition(Some(&job), JobOutcome::ToolFailed, true, 1, &settings),
            Transition::Requeue {
                consume_attempt: false,
                ..
            }
        ));
    }
}
