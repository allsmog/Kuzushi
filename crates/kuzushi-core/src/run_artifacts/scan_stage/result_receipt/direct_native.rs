//! Authenticate a direct producer's scope without consulting today's filesystem.
use super::*;
use serde_json::json;
mod scope;

pub(super) fn validate(
    target: &Path,
    run: &str,
    tool: &str,
    result: &Value,
    receipt: Option<&PhaseStageReceipt>,
) -> Result<()> {
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let scan = receipt
        .scan
        .as_ref()
        .context("Direct scan coverage is unavailable")?;
    let [engine] = scan.engines.as_slice() else {
        anyhow::bail!("Direct scan requires one engine");
    };
    let id = tool
        .strip_suffix(":scan")
        .context("Invalid direct scan producer")?;
    validate_identity(run, id, receipt, scan, engine)?;
    validate_outcome(result, receipt, engine)?;
    validate_rules(id, result, engine)?;
    scope::validate(target, id, result, scan)
}

fn validate_identity(
    run: &str,
    id: &str,
    receipt: &PhaseStageReceipt,
    scan: &ScanStageData,
    engine: &ScanStageEngine,
) -> Result<()> {
    anyhow::ensure!(
        receipt.run_refs == [run] && engine.run_ref.as_deref() == Some(run),
        "Direct scan cannot borrow another run's coverage"
    );
    anyhow::ensure!(
        engine.engine == id && scan.plan.engines == [id],
        "Direct scan names another engine"
    );
    anyhow::ensure!(
        scan.plan.selection == "direct",
        "Direct scan has another selection policy"
    );
    anyhow::ensure!(
        scan.artifact_delta
            == [ScanArtifactDelta {
                run_ref: run.into(),
                path: "findings.json".into()
            }],
        "Direct scan observation artifact differs from its run"
    );
    Ok(())
}

fn validate_outcome(
    result: &Value,
    receipt: &PhaseStageReceipt,
    engine: &ScanStageEngine,
) -> Result<()> {
    use crate::module_result::{tool_result_status, ToolResultStatus};
    let expected = match tool_result_status(result) {
        ToolResultStatus::Completed => (
            PhaseStageOutcome::Completed,
            ScanEngineStageOutcome::Complete,
        ),
        ToolResultStatus::Partial => (PhaseStageOutcome::Partial, ScanEngineStageOutcome::Partial),
        _ => anyhow::bail!("An unsuccessful direct scan cannot establish coverage"),
    };
    anyhow::ensure!(
        (receipt.outcome, engine.outcome) == expected,
        "Direct scan outcome contradicts its result"
    );
    if receipt.outcome == PhaseStageOutcome::Completed {
        anyhow::ensure!(
            result.pointer("/data/sourceCheckCurrent") == Some(&json!(true)),
            "Completed direct scan source was not authenticated"
        );
    }
    Ok(())
}

fn validate_rules(id: &str, result: &Value, engine: &ScanStageEngine) -> Result<()> {
    match id {
        "iac-scan" => validate_iac_rules(result, engine),
        "cargo-audit" => {
            anyhow::ensure!(
                engine.rule_ids.is_none(),
                "Cargo advisory policy is not recorded by this producer"
            );
            Ok(())
        }
        _ => anyhow::bail!("Unsupported direct scan producer"),
    }
}

fn validate_iac_rules(result: &Value, engine: &ScanStageEngine) -> Result<()> {
    let kind = result
        .pointer("/data/kind")
        .and_then(Value::as_str)
        .context("IaC rule family is unavailable")?;
    let families: &[&str] = match kind {
        "dockerfile" => &["dockerfile"],
        "github-actions" => &["actions"],
        "terraform" => &["terraform"],
        "all" => &["dockerfile", "actions", "terraform"],
        _ => anyhow::bail!("Invalid IaC rule family"),
    };
    let rules = engine
        .rule_ids
        .as_ref()
        .context("IaC rule policy is unavailable")?;
    anyhow::ensure!(!rules.is_empty(), "IaC rule policy is empty");
    anyhow::ensure!(
        rules.iter().all(|rule| families
            .iter()
            .any(|family| rule.starts_with(&format!("iac-scan/{family}-")))),
        "IaC policy includes another rule family"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
