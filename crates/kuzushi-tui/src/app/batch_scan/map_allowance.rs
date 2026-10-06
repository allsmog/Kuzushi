//! Bind a new scan form to the accepted Map's durable investigation accounting.
use super::BatchScanConfig;

pub(super) fn restore_map_allowance(config: &mut BatchScanConfig) {
    let result = kuzushi_core::capabilities::campaign::load_accepted_map_allowance(&config.target);
    apply_map_allowance(config, result);
}

pub(super) fn restore_map_history_allowance(config: &mut BatchScanConfig) {
    let result =
        kuzushi_core::capabilities::campaign::load_selected_map_history_allowance(&config.target);
    apply_map_allowance(config, result);
}

fn apply_map_allowance(
    config: &mut BatchScanConfig,
    result: anyhow::Result<Option<kuzushi_core::allowance::AllowanceSnapshot>>,
) {
    match result {
        Ok(Some(allowance)) => {
            config.notice = Some(format!("Calls: {} committed / {} total\nAvailable: {} context/scan · {} protected review\nRecorded Map investigation retained. Approve new work separately.",
                allowance.committed_calls, allowance.limits.max_provider_calls,
                allowance.remaining_discovery_calls(), allowance.protected_review_remaining()));
            config.study.restore_allowance(allowance);
        }
        Ok(None) => {}
        Err(error) => {
            config.study.accounting_error = Some(format!("{error:#}"));
            config.notice = Some(format!("Study continuation unavailable.\n{error:#}\nNo work can start.\nRestore the recorded evidence and reopen this form."));
        }
    }
}

#[cfg(test)]
mod tests;
