use super::*;

pub(super) struct PlannerWorkerJob {
    pub(super) config: V2Config,
    pub(super) model: String,
    pub(super) thinking_level: Option<String>,
    pub(super) cwd: PathBuf,
    pub(super) goal: String,
    pub(super) phase_intent: Option<WorkflowPhase>,
    pub(super) metadata: ProposalRunMetadata,
    pub(super) cancel: ScanCancellation,
}

impl PlannerWorkerJob {
    pub(super) fn run(mut self, sink: JobEventSink) {
        let audit = AgentCallAudit::for_prompt(&self.model, PLAN_SYSTEM_PROMPT, &self.goal);
        let target = self.cwd.clone();
        let run_id = self.metadata.run_id.clone();
        let run = ProposalRun {
            target: &target,
            run_id: &run_id,
            kind: "plan",
            tool: "planner:propose",
        };
        let input = planner_input(&self.goal, self.phase_intent);
        let lifecycle = match self.start_lifecycle(&run, &input, &sink) {
            Ok(lifecycle) => lifecycle,
            Err(error) => return send_plan_start_failure(&sink, error, audit),
        };
        let cancellation = self.cancel.disposition();
        let result = self.execute(lifecycle.observation(), sink.clone());
        let event = settle_planner_result(&run, lifecycle, result, audit, cancellation);
        sink.send(ShellEvent::Plan(event));
    }

    fn execute(
        self,
        observation: kuzushi_core::run_lifecycle::RunObservationHandle,
        sink: JobEventSink,
    ) -> CostedWorkerResult<PlanProposal> {
        run_planner_worker(
            self.config,
            self.model,
            self.thinking_level,
            self.cwd,
            &self.goal,
            self.phase_intent,
            observation,
            self.metadata.run_id,
            sink,
            self.cancel,
        )
    }

    fn start_lifecycle(
        &mut self,
        run: &ProposalRun<'_>,
        input: &serde_json::Value,
        sink: &JobEventSink,
    ) -> anyhow::Result<ProposalRunLifecycle> {
        start_planner_lifecycle(
            run,
            input,
            self.model.clone(),
            &self.config,
            std::mem::take(&mut self.metadata.loaded_modules),
            sink,
        )
    }
}
