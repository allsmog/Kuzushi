use super::{required_string, BatchTrialReport};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

pub(in crate::findings::application::batch_occurrence) fn validate_batch_trial_receipts(
    root: &Path,
    plan: &Value,
    queue: Option<&Value>,
    trials: &[BatchTrialReport],
) -> Result<()> {
    let batch_id = required_string(plan, "batchId")?;
    let expected_key = required_string(plan, "equivalenceKey")?;
    let equivalence = plan
        .get("equivalence")
        .context("scan-batch plan is missing equivalence receipt")?;
    let expected_config = required_string(equivalence, "configSha256")?;
    let expected_model = equivalence.get("model").and_then(Value::as_str);
    let expected_provider = equivalence
        .pointer("/runtimeIdentity/provider")
        .and_then(Value::as_str);
    let receiptless = receiptless_attempts(queue);
    let expected = ExpectedTrialReceipt {
        batch_id: &batch_id,
        key: &expected_key,
        config: &expected_config,
        model: expected_model,
        provider: expected_provider,
        receiptless: &receiptless,
    };
    for trial in trials {
        validate_trial_receipt(root, trial, &expected)?;
    }
    validate_engine_receipt_sets(root, trials)
}

struct ExpectedTrialReceipt<'a> {
    batch_id: &'a str,
    key: &'a str,
    config: &'a str,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    receiptless: &'a BTreeSet<(String, String)>,
}

fn validate_trial_receipt(
    root: &Path,
    trial: &BatchTrialReport,
    expected: &ExpectedTrialReceipt<'_>,
) -> Result<()> {
    validate_attempt_presence(trial)?;
    let mut authenticated = false;
    for run_id in &trial.attempt_run_ids {
        authenticated |= authenticate_attempt(
            root,
            trial,
            run_id,
            expected,
        )?;
    }
    validate_completed_trial_authentication(trial, authenticated)
}

fn validate_attempt_presence(trial: &BatchTrialReport) -> Result<()> {
    if !trial.attempt_run_ids.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        trial.attempts == 0,
        "batch trial {} records attempts without attempt run ids",
        trial.job_id
    );
    anyhow::ensure!(
        trial.state != "completed",
        "completed batch trial {} has no authenticated attempt receipt",
        trial.job_id
    );
    anyhow::ensure!(
        attemptless_state_is_valid(&trial.state),
        "batch trial {} in state {:?} cannot omit attempt run ids",
        trial.job_id,
        trial.state
    );
    Ok(())
}

fn attemptless_state_is_valid(state: &str) -> bool {
    matches!(state, "planned" | "pending" | "parked" | "failed")
}

fn authenticate_attempt(
    root: &Path,
    trial: &BatchTrialReport,
    run_id: &str,
    expected: &ExpectedTrialReceipt<'_>,
) -> Result<bool> {
    let Some(summary) = attempt_summary(root, trial, run_id, expected.receiptless)? else {
        return Ok(false);
    };
    validate_child_equivalence_receipt(root, trial, run_id, expected.batch_id, expected.key)?;
    validate_runtime_receipt(trial, &summary, expected.config, expected.model)?;
    ensure_receipt_provider(&trial.job_id, &summary, expected.provider)?;
    Ok(true)
}

fn validate_runtime_receipt(
    trial: &BatchTrialReport,
    summary: &crate::run_artifacts::RunSummary,
    expected_config: &str,
    expected_model: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(
        summary.config_hash.as_deref() == Some(expected_config),
        "batch trial {} used a mixed runtime/config receipt",
        trial.job_id
    );
    anyhow::ensure!(
        summary.model.as_deref() == expected_model,
        "batch trial {} used a mixed model receipt",
        trial.job_id
    );
    Ok(())
}

fn validate_completed_trial_authentication(
    trial: &BatchTrialReport,
    authenticated: bool,
) -> Result<()> {
    anyhow::ensure!(
        trial.state != "completed" || authenticated,
        "completed batch trial {} has no authenticated attempt receipt",
        trial.job_id
    );
    Ok(())
}

fn validate_child_equivalence_receipt(
    root: &Path,
    trial: &BatchTrialReport,
    run_id: &str,
    batch_id: &str,
    expected_key: &str,
) -> Result<()> {
    let receipt =
        crate::capabilities::campaign::load_scan_batch_child_equivalence_receipt(root, run_id)
            .with_context(|| {
                format!(
                    "batch trial {} attempt {run_id} lacks child-consumption equivalence evidence",
                    trial.job_id
                )
            })?;
    anyhow::ensure!(
        receipt.batch_id == batch_id
            && receipt.trial == trial.trial
            && receipt.expected_key == expected_key,
        "batch trial {} attempt {run_id} has a mismatched child equivalence receipt",
        trial.job_id
    );
    Ok(())
}

fn attempt_summary(
    root: &Path,
    trial: &BatchTrialReport,
    run_id: &str,
    receiptless: &BTreeSet<(String, String)>,
) -> Result<Option<crate::run_artifacts::RunSummary>> {
    match crate::run_artifacts::load_run_summary(root, run_id) {
        Ok(summary) => Ok(Some(summary)),
        Err(_) if receiptless.contains(&(trial.job_id.clone(), run_id.to_string())) => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "batch trial {} attempt {run_id} has no receipt",
                trial.job_id
            )
        }),
    }
}

fn receiptless_attempts(queue: Option<&Value>) -> BTreeSet<(String, String)> {
    let mut attempts = BTreeSet::new();
    let Some(jobs) = queue
        .and_then(|value| value.get("jobs"))
        .and_then(Value::as_object)
    else {
        return attempts;
    };
    for (job_id, job) in jobs {
        collect_receiptless_job_attempts(job_id, job, &mut attempts);
    }
    attempts
}

fn collect_receiptless_job_attempts(
    job_id: &str,
    job: &Value,
    attempts: &mut BTreeSet<(String, String)>,
) {
    for attempt in job
        .get("attemptRuns")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if attempt.get("outcome").and_then(Value::as_str)
            != Some(crate::capabilities::campaign::RECEIPTLESS_ATTEMPT_OUTCOME)
        {
            continue;
        }
        if let Some(run_id) = attempt.get("runId").and_then(Value::as_str) {
            attempts.insert((job_id.to_string(), run_id.to_string()));
        }
    }
}

fn ensure_receipt_provider(
    job_id: &str,
    summary: &crate::run_artifacts::RunSummary,
    expected_provider: Option<&str>,
) -> Result<()> {
    let mixed = summary
        .llm_calls
        .iter()
        .any(|call| Some(call.provider.as_str()) != expected_provider);
    anyhow::ensure!(!mixed, "batch trial {job_id} used a mixed provider receipt");
    Ok(())
}

fn validate_engine_receipt_sets(root: &Path, trials: &[BatchTrialReport]) -> Result<()> {
    let receipts = trials
        .iter()
        .filter(|trial| trial.state == "completed")
        .map(|trial| Ok((trial.job_id.as_str(), load_engine_receipt(root, trial)?)))
        .collect::<Result<Vec<_>>>()?;
    ensure_consistent_engine_receipts(&receipts)
}

fn load_engine_receipt(root: &Path, trial: &BatchTrialReport) -> Result<Vec<String>> {
    let run_id = trial
        .run_id
        .as_deref()
        .with_context(|| format!("completed batch trial {} has no runId", trial.job_id))?;
    let outcome = crate::run_artifacts::load_persisted_run_terminal_outcome(root, run_id)
        .with_context(|| {
            format!(
                "completed batch trial {} has no result receipt",
                trial.job_id
            )
        })?;
    outcome
        .result
        .pointer("/data/engines")
        .and_then(Value::as_array)
        .context("completed batch result receipt is missing data.engines")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .context("batch result engine receipt contains a non-string")
        })
        .collect()
}

fn ensure_consistent_engine_receipts(receipts: &[(&str, Vec<String>)]) -> Result<()> {
    let Some((_, expected)) = receipts.first() else {
        return Ok(());
    };
    for (job_id, engines) in receipts.iter().skip(1) {
        anyhow::ensure!(
            engines == expected,
            "batch trial {job_id} used a mixed engine receipt"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_engine_sets_are_not_comparable() {
        let receipts = [
            ("trial-001", vec!["semgrep".to_string()]),
            ("trial-002", vec!["secret-scan".to_string()]),
        ];
        let error = ensure_consistent_engine_receipts(&receipts).unwrap_err();
        assert!(error.to_string().contains("mixed engine receipt"));
    }
}
