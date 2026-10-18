use super::*;
use kuzushi_core::allowance::AllowanceSnapshot;

impl ShellApp {
    pub(super) fn refresh_dfd_parent_accounting(&mut self, child: &BatchScanConfig) {
        let Some(receipt) = child.study.receipt.as_ref() else {
            return;
        };
        let Some(parent) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if receipt.investigation_id.as_deref() != Some(&parent.study.investigation_id) {
            return;
        }
        let required = child.study.allowance.is_some() || parent.study.allowance.is_some();
        let result =
            kuzushi_core::capabilities::campaign::load_study_allowance(&parent.target, receipt);
        apply_return_accounting(parent, result, required);
    }
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
