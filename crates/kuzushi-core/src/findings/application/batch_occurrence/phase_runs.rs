//! Successful current trials supply completion; every attempt remains evidence.
use super::{BatchOccurrenceReport, BatchTrialReport};
use anyhow::{Context, Result};

impl BatchOccurrenceReport {
    pub(crate) fn phase_result_run_ids(&self) -> Result<Vec<String>> {
        if self.completed != self.planned || self.planned == 0 {
            return Ok(self.all_attempt_run_ids());
        }
        anyhow::ensure!(
            self.trials.len() == self.planned,
            "completed batch has missing trials"
        );
        let mut runs = self
            .trials
            .iter()
            .map(completed_trial_run)
            .collect::<Result<Vec<_>>>()?;
        runs.sort();
        runs.dedup();
        Ok(runs)
    }
}

fn completed_trial_run(trial: &BatchTrialReport) -> Result<String> {
    anyhow::ensure!(
        trial.state == "completed",
        "completed batch contains an unfinished trial"
    );
    trial
        .run_id
        .clone()
        .context("completed trial has no current run")
}
