use super::run_exit::{run_exit_code, RunCommandExit, EXIT_RUN_CANCELED};
use anyhow::Result;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_canceled_observed, try_record_tool_run_canceled_settled,
    try_record_tool_run_interrupted_observed, try_record_tool_run_interrupted_settled,
    ToolRunRecord,
};
use kuzushi_core::run_lifecycle::{RunItemStatus, RunObservationHandle};
use kuzushi_core::scan::{CancellationDisposition, ScanCancellation};
use std::path::Path;

/// Two-stage SIGINT policy for the headless `scan` surface.
///
/// The first signal requests cooperative cancellation so scanners, model
/// bridges, and managed subprocess groups can stop and the host can persist one
/// authoritative terminal outcome. A second signal is the explicit emergency
/// escape hatch and retains the established batch exit code.
pub(crate) struct ScanSignalWatcher {
    task: tokio::task::JoinHandle<()>,
}

impl ScanSignalWatcher {
    pub(crate) fn install(cancellation: ScanCancellation) -> Option<Self> {
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        let task = runtime.spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancellation.cancel();
            }
            if tokio::signal::ctrl_c().await.is_ok() {
                std::process::exit(EXIT_RUN_CANCELED);
            }
        });
        Some(Self { task })
    }
}

impl Drop for ScanSignalWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn settle_scan_cancellation_settled(
    record: ToolRunRecord<'_>,
    disposition: CancellationDisposition,
    observation: &RunObservationHandle,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> Result<serde_json::Value> {
    match disposition {
        CancellationDisposition::Canceled => try_record_tool_run_canceled_settled(
            record,
            cancellation_reason(disposition),
            observation,
            completion,
        )?,
        CancellationDisposition::Interrupted => try_record_tool_run_interrupted_settled(
            record,
            cancellation_reason(disposition),
            observation,
            completion,
        )?,
    }
    persisted_cancellation_result(record, disposition)
}

pub(crate) fn settle_scan_cancellation_observed(
    record: ToolRunRecord<'_>,
    disposition: CancellationDisposition,
    observation: Option<&RunObservationHandle>,
) -> Result<serde_json::Value> {
    match disposition {
        CancellationDisposition::Canceled => try_record_tool_run_canceled_observed(
            record,
            cancellation_reason(disposition),
            observation,
        )?,
        CancellationDisposition::Interrupted => try_record_tool_run_interrupted_observed(
            record,
            cancellation_reason(disposition),
            observation,
        )?,
    }
    persisted_cancellation_result(record, disposition)
}

/// Convert only a host-persisted cancellation/interruption into the shared
/// deterministic batch exit. Tool- or model-authored JSON cannot select 130.
pub(crate) fn scan_terminal_exit_error(
    target: &Path,
    run_id: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    let message = error.to_string();
    persisted_scan_terminal_exit_error(target, run_id, &message).unwrap_or(error)
}

pub(crate) fn persisted_scan_terminal_exit_error(
    target: &Path,
    run_id: &str,
    message: &str,
) -> Option<anyhow::Error> {
    let Ok(persisted) = kuzushi_core::load_persisted_run_terminal_outcome(target, run_id) else {
        return None;
    };
    if !matches!(
        persisted.status,
        RunItemStatus::Canceled | RunItemStatus::Interrupted
    ) {
        return None;
    }
    Some(anyhow::Error::new(RunCommandExit::new(
        run_exit_code(persisted.status),
        message,
    )))
}

fn persisted_cancellation_result(
    record: ToolRunRecord<'_>,
    disposition: CancellationDisposition,
) -> Result<serde_json::Value> {
    let persisted =
        kuzushi_core::load_persisted_run_terminal_outcome(record.target, record.run_id)?;
    let expected = disposition_status(disposition);
    anyhow::ensure!(
        persisted.status == expected,
        "persisted scan cancellation status disagrees with the requested disposition"
    );
    Ok(persisted.result)
}

const fn disposition_status(disposition: CancellationDisposition) -> RunItemStatus {
    match disposition {
        CancellationDisposition::Canceled => RunItemStatus::Canceled,
        CancellationDisposition::Interrupted => RunItemStatus::Interrupted,
    }
}

const fn cancellation_reason(disposition: CancellationDisposition) -> &'static str {
    match disposition {
        CancellationDisposition::Canceled => "operator canceled headless scan",
        CancellationDisposition::Interrupted => "headless scan was interrupted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility;

    #[test]
    fn observed_cancellation_persists_one_host_owned_terminal_truth() {
        let target = tempfile::tempdir().unwrap();
        let (record, observation) = started_scan(target.path(), "scan-canceled", "sast:scan");

        let output = settle_scan_cancellation_observed(
            record,
            CancellationDisposition::Canceled,
            Some(&observation),
        )
        .unwrap();

        assert_eq!(output["status"], "canceled");
        assert_eq!(output["ok"], false);
        assert_terminal_truth(target.path(), "scan-canceled", RunItemStatus::Canceled);
    }

    #[test]
    fn cancellation_after_dispatch_overrides_a_success_shaped_result() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "scan-interrupted";
        let tool = "sast:scan";
        let (record, observation) = started_scan(target.path(), run_id, tool);
        let input = serde_json::json!({"runId": run_id});
        let call =
            kuzushi_core::ApplicationToolCall::start(observation.clone(), tool, &input, None, None)
                .unwrap();
        let execution: anyhow::Result<serde_json::Value> = Ok(serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "must not outrun interruption",
            "data": {"runId": run_id}
        }));
        let completion = call.completion_from_result(&execution);

        let output = settle_scan_cancellation_settled(
            record,
            CancellationDisposition::Interrupted,
            &observation,
            completion,
        )
        .unwrap();

        assert_eq!(output["status"], "interrupted");
        assert_eq!(output["ok"], false);
        let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id)
            .unwrap()
            .projection;
        assert_eq!(
            projection.terminal.map(|terminal| terminal.status),
            Some(RunItemStatus::Interrupted)
        );
        assert_eq!(
            projection.calls.values().next().map(|call| call.status),
            Some(RunItemStatus::Interrupted)
        );
        assert_terminal_truth(target.path(), run_id, RunItemStatus::Interrupted);
    }

    #[test]
    fn persisted_scan_cancellation_selects_the_batch_exit_code() {
        for (run_id, disposition, expected_code) in [
            ("scan-exit-canceled", CancellationDisposition::Canceled, 130),
            (
                "scan-exit-interrupted",
                CancellationDisposition::Interrupted,
                3,
            ),
        ] {
            let target = tempfile::tempdir().unwrap();
            let (record, observation) = started_scan(target.path(), run_id, "sast:scan");
            settle_scan_cancellation_observed(record, disposition, Some(&observation)).unwrap();

            let error =
                scan_terminal_exit_error(target.path(), run_id, anyhow::anyhow!("terminal scan"));
            let exit = error
                .downcast::<RunCommandExit>()
                .expect("persisted cancellation must carry a typed batch exit");
            assert_eq!(exit.code(), expected_code);
        }
    }

    #[test]
    fn cancellation_wording_without_host_terminal_truth_cannot_select_exit_130() {
        let target = tempfile::tempdir().unwrap();
        let error = scan_terminal_exit_error(
            target.path(),
            "unpersisted-model-output",
            anyhow::anyhow!("model claimed status=canceled"),
        );

        assert!(error.downcast_ref::<RunCommandExit>().is_none());
        assert_eq!(error.to_string(), "model claimed status=canceled");
    }

    fn started_scan<'a>(
        target: &'a Path,
        run_id: &'a str,
        tool: &'a str,
    ) -> (ToolRunRecord<'a>, RunObservationHandle) {
        let record = ToolRunRecord::new(target, run_id, "scan", tool);
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({"runId": run_id}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let observation = RunObservationHandle::jsonl(target, run_id)
            .unwrap()
            .start_root_task("Run the accepted Scan plan")
            .unwrap();
        observation
            .task_handle()
            .unwrap()
            .update_and_flush(RunItemStatus::Running, None)
            .unwrap();
        (record, observation)
    }

    fn assert_terminal_truth(target: &Path, run_id: &str, expected: RunItemStatus) {
        let persisted = kuzushi_core::load_persisted_run_terminal_outcome(target, run_id).unwrap();
        assert_eq!(persisted.status, expected);
        assert_eq!(persisted.result["status"], expected.label());
        assert_eq!(
            kuzushi_core::load_run_summary(target, run_id)
                .unwrap()
                .status,
            expected.label()
        );
    }
}
