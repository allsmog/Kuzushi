use kuzushi_core::ScanCancellation;

#[derive(Debug, Default)]
pub(crate) struct ToolRunState {
    running: Option<String>,
    cancel: Option<ScanCancellation>,
    ambient: Option<String>,
    run_id: Option<String>,
    active_model_override: Option<String>,
    abort_requested: bool,
}

impl ToolRunState {
    pub(crate) fn active_name(&self) -> Option<&str> {
        self.running.as_deref()
    }

    pub(crate) fn active_name_owned(&self) -> Option<String> {
        self.running.clone()
    }

    pub(crate) fn is_running(&self) -> bool {
        self.running.is_some()
    }

    pub(crate) fn cancel(&self) -> Option<&ScanCancellation> {
        self.cancel.as_ref()
    }

    pub(crate) fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    pub(crate) fn take_run_id(&mut self) -> Option<String> {
        self.run_id.take()
    }

    pub(crate) fn active_model_override(&self) -> Option<&str> {
        self.active_model_override.as_deref()
    }

    pub(crate) fn set_active_model_override(&mut self, model: Option<String>) {
        self.active_model_override = model;
    }

    pub(crate) fn abort_requested(&self) -> bool {
        self.abort_requested
    }

    pub(crate) fn request_abort(&mut self) {
        self.abort_requested = true;
    }

    pub(crate) fn is_ambient(&self, name: &str) -> bool {
        self.ambient.as_deref() == Some(name)
    }

    pub(crate) fn start(
        &mut self,
        tool_name: String,
        cancel: ScanCancellation,
        run_id: String,
        model_override: Option<String>,
    ) {
        self.running = Some(tool_name);
        self.cancel = Some(cancel);
        self.ambient = None;
        self.run_id = Some(run_id);
        self.active_model_override = model_override;
        self.abort_requested = false;
    }

    pub(crate) fn finish(&mut self) {
        self.running = None;
        self.cancel = None;
        self.ambient = None;
        self.active_model_override = None;
        self.abort_requested = false;
    }

    pub(crate) fn clear_finished_run_slot(&mut self) {
        self.cancel = None;
        self.abort_requested = false;
    }

    #[cfg(test)]
    pub(crate) fn set_running_for_test(&mut self, tool_name: Option<String>) {
        self.running = tool_name;
    }

    #[cfg(test)]
    pub(crate) fn set_cancel_for_test(&mut self, cancel: Option<ScanCancellation>) {
        self.cancel = cancel;
    }

    #[cfg(test)]
    pub(crate) fn set_run_id_for_test(&mut self, run_id: Option<String>) {
        self.run_id = run_id;
    }

    #[cfg(test)]
    pub(crate) fn set_abort_requested_for_test(&mut self, requested: bool) {
        self.abort_requested = requested;
    }

    #[cfg(test)]
    pub(crate) fn set_ambient_for_test(&mut self, tool_name: Option<String>) {
        self.ambient = tool_name;
    }
}
