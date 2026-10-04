use super::*;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageResumeHealth {
    pub degraded: bool,
    pub checkpoint_cleared: bool,
    pub last_durable_stage: Option<String>,
    pub last_durable_run_id: Option<String>,
    pub retry_on_next_dispatch: bool,
    pub problems: Vec<StageResumeProblem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageResumeProblem {
    pub operation: String,
    pub class: String,
    pub message: String,
}

impl StageResumeHealth {
    pub(super) fn from_prior(prior: &[ToolStageReceipt], run_id: Option<String>) -> Self {
        Self {
            last_durable_stage: prior.last().map(|receipt| bounded_stage(&receipt.stage)),
            last_durable_run_id: run_id,
            ..Self::default()
        }
    }
}

impl StageCheckpointHandle {
    pub(crate) fn with_trace(mut self, trace: Option<TraceHandle>) -> Self {
        self.trace = trace;
        for problem in &self.resume_health().problems {
            self.emit_resume_problem(problem);
        }
        self
    }

    pub fn resume_health(&self) -> StageResumeHealth {
        self.health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_else(|_| StageResumeHealth {
                degraded: true,
                retry_on_next_dispatch: true,
                ..StageResumeHealth::default()
            })
    }

    pub(super) fn resume_problem(&self, operation: &str, error: &anyhow::Error) {
        let problem = problem(operation, error);
        if self.remember_problem(&problem) {
            self.emit_resume_problem(&problem);
        }
        self.persist_resume_health();
    }

    fn remember_problem(&self, problem: &StageResumeProblem) -> bool {
        let Ok(mut health) = self.health.lock() else {
            return false;
        };
        health.degraded = true;
        health.retry_on_next_dispatch = true;
        if health
            .problems
            .iter()
            .any(|prior| prior.operation == problem.operation && prior.class == problem.class)
        {
            return false;
        }
        health.problems.push(problem.clone());
        true
    }

    fn emit_resume_problem(&self, problem: &StageResumeProblem) {
        if let Some(trace) = &self.trace {
            trace
                .step(
                    "warning",
                    "checkpoint",
                    format!(
                        "resume degraded: {} failed ({}): {}; recovery retries on next dispatch",
                        problem.operation, problem.class, problem.message
                    ),
                )
                .with_severity("warning")
                .emit();
        }
    }

    pub(super) fn saved_checkpoint(&self, state: &StageCheckpointState) {
        if let Ok(mut health) = self.health.lock() {
            health.last_durable_stage = state
                .completed_now
                .last()
                .or_else(|| state.prior.last())
                .map(|receipt| bounded_stage(&receipt.stage));
            health.last_durable_run_id = Some(self.run_id.clone());
        }
        self.persist_resume_health();
    }

    pub(super) fn persist_resume_health(&self) {
        let Ok(value) = serde_json::to_value(self.resume_health()) else {
            return;
        };
        if let Err(error) = write_run_artifact_json_bounded(
            &self.target,
            &self.run_id,
            "resume-health.json",
            "stage checkpoint health",
            &value,
            16 * 1024,
        ) {
            let problem = problem("health-receipt", &error);
            if self.remember_problem(&problem) {
                self.emit_resume_problem(&problem);
            }
        }
    }
}

fn problem(operation: &str, error: &anyhow::Error) -> StageResumeProblem {
    StageResumeProblem {
        operation: operation.into(),
        class: error_class(error),
        message: error.to_string().chars().take(512).collect(),
    }
}

fn bounded_stage(stage: &str) -> String {
    stage.chars().take(256).collect()
}

fn error_class(error: &anyhow::Error) -> String {
    error.downcast_ref::<std::io::Error>().map_or_else(
        || "checkpoint-limit-or-persistence".into(),
        |error| format!("{:?}", error.kind()).to_ascii_lowercase(),
    )
}
