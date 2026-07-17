use super::ProposalRun;
use anyhow::{Context, Result};
use kuzushi_core::run_lifecycle::{RunItemStatus, RunObservationHandle, SafeText};
use kuzushi_core::runtime::RuntimeCostReport;
use kuzushi_core::{ApplicationToolCall, V2Config};
use serde_json::Value;

pub(in crate::app::workers) struct ProposalRunLifecycle {
    observation: RunObservationHandle,
    call: ApplicationToolCall,
}

impl ProposalRunLifecycle {
    pub(in crate::app::workers) fn observation(&self) -> RunObservationHandle {
        self.call.execution_observation()
    }
}

impl ProposalRun<'_> {
    pub(in crate::app::workers) fn start_observed(
        &self,
        input: &Value,
        model: String,
        config: &V2Config,
        loaded_modules: Vec<String>,
        observation: RunObservationHandle,
    ) -> Result<ProposalRunLifecycle> {
        self.start(input, model.clone(), config, loaded_modules)?;
        start_proposal_task(&observation)?;
        let call = ApplicationToolCall::start(
            observation.clone(),
            self.tool,
            input,
            Some("agent"),
            Some(&model),
        )
        .inspect_err(|error| fail_unsettled_start(self, error));
        Ok(ProposalRunLifecycle {
            observation,
            call: call?,
        })
    }

    pub(in crate::app::workers) fn complete_observed(
        &self,
        summary: &str,
        proposal: Value,
        cost: RuntimeCostReport,
        lifecycle: ProposalRunLifecycle,
    ) -> Result<()> {
        let result = super::completed_result(summary, proposal, cost);
        let completion = lifecycle.call.completion_from_result(&Ok(result.clone()));
        kuzushi_core::run_artifacts::try_record_tool_run_complete_settled(
            self.record(),
            &result,
            &lifecycle.observation,
            completion,
        )
        .context("could not persist the proposal result")
    }

    pub(in crate::app::workers) fn fail_observed(
        &self,
        error: &str,
        cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
        cost: RuntimeCostReport,
        lifecycle: ProposalRunLifecycle,
    ) -> Result<()> {
        let status = failure_status(cancellation);
        let completion = lifecycle.call.completion(status, cost, Vec::new(), 0, 1);
        match cancellation {
            Some(kuzushi_core::scan::CancellationDisposition::Canceled) => {
                kuzushi_core::run_artifacts::try_record_tool_run_canceled_settled(
                    self.record(),
                    error,
                    &lifecycle.observation,
                    completion,
                )
            }
            Some(kuzushi_core::scan::CancellationDisposition::Interrupted) => {
                kuzushi_core::run_artifacts::try_record_tool_run_interrupted_settled(
                    self.record(),
                    error,
                    &lifecycle.observation,
                    completion,
                )
            }
            None => kuzushi_core::run_artifacts::try_record_tool_run_failed_settled(
                self.record(),
                error,
                &lifecycle.observation,
                completion,
            ),
        }
    }
}

fn start_proposal_task(observation: &RunObservationHandle) -> Result<()> {
    observation
        .task_handle()
        .context("proposal run lacks its semantic task")?
        .update_and_flush(RunItemStatus::Running, None)?;
    Ok(())
}

fn fail_unsettled_start(run: &ProposalRun<'_>, error: &anyhow::Error) {
    let _ = run.fail(
        &format!("proposal lifecycle could not start: {error}"),
        None,
    );
}

fn failure_status(
    cancellation: Option<kuzushi_core::scan::CancellationDisposition>,
) -> RunItemStatus {
    match cancellation {
        Some(kuzushi_core::scan::CancellationDisposition::Canceled) => RunItemStatus::Canceled,
        Some(kuzushi_core::scan::CancellationDisposition::Interrupted) => {
            RunItemStatus::Interrupted
        }
        None => RunItemStatus::Failed,
    }
}
