use super::*;

pub(super) struct ThreatWorkerJob {
    pub(super) config: V2Config,
    pub(super) model: String,
    pub(super) thinking_level: Option<String>,
    pub(super) cwd: PathBuf,
    pub(super) existing: serde_json::Value,
    pub(super) metadata: ProposalRunMetadata,
    pub(super) cancel: ScanCancellation,
}

impl ThreatWorkerJob {
    pub(super) fn run_regen(mut self, sink: JobEventSink) {
        let prompt = threat_regen_prompt(&self.existing);
        let audit = AgentCallAudit::for_prompt(&self.model, THREAT_PATCH_SYSTEM_PROMPT, &prompt);
        let target = self.cwd.clone();
        let run_id = self.metadata.run_id.clone();
        let run = ProposalRun {
            target: &target,
            run_id: &run_id,
            kind: "threat",
            tool: "threat-model:propose",
        };
        let input = threat_regen_input(&self.existing);
        let lifecycle =
            match self.start_lifecycle(&run, &input, &sink, "Build the threat-model proposal") {
                Ok(lifecycle) => lifecycle,
                Err(error) => return send_threat_start_failure(&sink, error, audit),
            };
        let cancellation = self.cancel.disposition();
        let result = self.execute_regen(lifecycle.observation());
        let event = settle_threat_regen_result(&run, lifecycle, result, audit, cancellation);
        sink.send(ShellEvent::Threat(event));
    }

    fn execute_regen(
        self,
        observation: kuzushi_core::run_lifecycle::RunObservationHandle,
    ) -> CostedWorkerResult<ThreatPatch> {
        run_threat_regen_worker(
            self.config,
            self.model,
            self.thinking_level,
            self.cwd,
            self.existing,
            observation,
            self.cancel,
        )
    }

    pub(super) fn run_ask(mut self, question: String, sink: JobEventSink) {
        let prompt = threat_ask_prompt(&question, &self.existing);
        let audit = AgentCallAudit::for_prompt(&self.model, ASK_SYSTEM_PROMPT, &prompt);
        let target = self.cwd.clone();
        let run_id = self.metadata.run_id.clone();
        let run = ProposalRun {
            target: &target,
            run_id: &run_id,
            kind: "threat",
            tool: "threat-model:ask",
        };
        let input = threat_ask_input(&self.existing, &question);
        let lifecycle =
            match self.start_lifecycle(&run, &input, &sink, "Answer the threat-model question") {
                Ok(lifecycle) => lifecycle,
                Err(error) => return send_threat_start_failure(&sink, error, audit),
            };
        let cancellation = self.cancel.disposition();
        let result = self.execute_ask(&question, lifecycle.observation());
        let event = settle_threat_ask_result(&run, lifecycle, result, audit, cancellation);
        sink.send(ShellEvent::Threat(event));
    }

    fn execute_ask(
        self,
        question: &str,
        observation: kuzushi_core::run_lifecycle::RunObservationHandle,
    ) -> CostedWorkerResult<String> {
        run_threat_ask_worker(
            self.config,
            self.model,
            self.thinking_level,
            self.cwd,
            self.existing,
            question,
            observation,
            self.cancel,
        )
    }

    fn start_lifecycle(
        &mut self,
        run: &ProposalRun<'_>,
        input: &serde_json::Value,
        sink: &JobEventSink,
        task_title: &str,
    ) -> anyhow::Result<ProposalRunLifecycle> {
        start_threat_lifecycle(
            run,
            input,
            self.model.clone(),
            &self.config,
            std::mem::take(&mut self.metadata.loaded_modules),
            sink,
            task_title,
        )
    }
}
