use super::{TerminalLoopWake, WorkerHandleRegistry};
use kuzushi_core::ScanCancellation;

#[derive(Debug, Default)]
pub(crate) struct RuntimeState {
    worker_handles: WorkerHandleRegistry,
    loop_wake: Option<TerminalLoopWake>,
    scan_cancel: Option<ScanCancellation>,
    agent_cancel: Option<ScanCancellation>,
    plan_cancel: Option<ScanCancellation>,
    threat_cancel: Option<ScanCancellation>,
}

impl RuntimeState {
    #[cfg(test)]
    pub(crate) fn worker_handles(&self) -> &WorkerHandleRegistry {
        &self.worker_handles
    }

    pub(crate) fn worker_handles_mut(&mut self) -> &mut WorkerHandleRegistry {
        &mut self.worker_handles
    }

    pub(crate) fn set_loop_wake(&mut self, wake: Option<TerminalLoopWake>) {
        self.loop_wake = wake;
    }

    pub(crate) fn scan_cancel(&self) -> Option<&ScanCancellation> {
        self.scan_cancel.as_ref()
    }

    pub(crate) fn set_scan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.scan_cancel = cancel;
    }

    pub(crate) fn agent_cancel(&self) -> Option<&ScanCancellation> {
        self.agent_cancel.as_ref()
    }

    pub(crate) fn set_agent_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.agent_cancel = cancel;
    }

    pub(crate) fn plan_cancel(&self) -> Option<&ScanCancellation> {
        self.plan_cancel.as_ref()
    }

    pub(crate) fn set_plan_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.plan_cancel = cancel;
    }

    pub(crate) fn threat_cancel(&self) -> Option<&ScanCancellation> {
        self.threat_cancel.as_ref()
    }

    pub(crate) fn set_threat_cancel(&mut self, cancel: Option<ScanCancellation>) {
        self.threat_cancel = cancel;
    }
}
