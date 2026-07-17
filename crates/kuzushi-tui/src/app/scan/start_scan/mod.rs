use super::*;

mod scan_event_routing;
mod scan_failure_events;
mod scan_labels;
mod scan_panel;
mod scan_request;
mod scan_startup;
mod scan_success_events;
mod scan_trace;

pub(crate) use scan_panel::queued_scan_panel;
pub(crate) use scan_request::{
    effective_scan_options, scan_input_with_run_id, scan_options_log_message, EffectiveScanOption,
    ScanStartRequest,
};
pub(crate) use scan_trace::scan_trace_handle;

impl ShellApp {
    fn checked_scan_terminal_cost(
        &self,
        run_id: &str,
        reported: kuzushi_core::runtime::RuntimeCostReport,
    ) -> anyhow::Result<kuzushi_core::runtime::RuntimeCostReport> {
        let Some(target) = self.scan_target_owned() else {
            return Ok(reported);
        };
        let traced = kuzushi_core::run_artifacts::trace_cost_report(target, run_id)?;
        kuzushi_core::run_artifacts::reconcile_terminal_cost_reports(
            reported,
            traced,
            "scan terminal",
        )
    }
}
