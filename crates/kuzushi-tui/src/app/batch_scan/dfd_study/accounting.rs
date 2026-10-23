use super::*;
use kuzushi_core::allowance::AllowanceSnapshot;

impl ShellApp {
    pub(super) fn refresh_dfd_parent_accounting(&mut self, child: &BatchScanConfig) {
        let Some(parent) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let required = child.study.allowance.is_some() || parent.study.allowance.is_some();
        let Some(result) =
            returned_accounting(child, &parent.target, &parent.study.investigation_id)
        else {
            return;
        };
        apply_return_accounting(parent, result, required);
    }
}

fn returned_accounting(
    child: &BatchScanConfig,
    target: &std::path::Path,
    investigation: &str,
) -> Option<anyhow::Result<Option<AllowanceSnapshot>>> {
    if let Some(receipt) = child
        .context_generation
        .as_ref()
        .and_then(|generation| generation.receipt.as_ref())
    {
        return (receipt.investigation_id == investigation).then(|| receipt.load_allowance(target));
    }
    child
        .study
        .receipt
        .as_ref()
        .filter(|receipt| receipt.investigation_id.as_deref() == Some(investigation))
        .map(|receipt| kuzushi_core::capabilities::campaign::load_study_allowance(target, receipt))
}

fn apply_return_accounting(
    parent: &mut BatchScanConfig,
    result: anyhow::Result<Option<AllowanceSnapshot>>,
    required: bool,
) {
    match result {
        Ok(None) if required => parent.study.accounting_error = Some(
            "Recorded investigation accounting is missing. Restore it before preparing more work."
                .into(),
        ),
        Ok(allowance) => parent.study.allowance = allowance,
        Err(error) => {
            parent.study.accounting_error = Some(format!(
                "Investigation accounting could not be refreshed: {error:#}"
            ))
        }
    }
}
