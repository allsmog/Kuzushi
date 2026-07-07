use super::*;
#[cfg(test)]
use kuzushi_core::ScanCancellation;

impl ShellApp {
    pub(crate) fn reduce_load_command(&mut self, specifier: Option<String>) -> Vec<ShellEffect> {
        self.shell_view = ShellView::Tools;
        let Some(specifier) = normalized_load_specifier(specifier) else {
            self.log(
                "error",
                "load requires a module specifier. Next: load builtin:sast or modules",
            );
            return Vec::new();
        };

        if let Some(module_id) = self.static_module_id_for_load_specifier(&specifier) {
            self.log(
                "load",
                format!(
                    "{specifier} is already available in the Rust static registry. Next: use {module_id}"
                ),
            );
            return Vec::new();
        }

        vec![ShellEffect::LoadDynamicModule(DynamicModuleLoad {
            specifier,
        })]
    }

    fn static_module_id_for_load_specifier(&self, specifier: &str) -> Option<String> {
        let module_id = specifier
            .strip_prefix("builtin:")
            .unwrap_or(specifier)
            .trim();
        if module_id.contains(':') {
            return None;
        }
        self.registry()
            .modules()
            .any(|module| module.metadata().id == module_id)
            .then(|| module_id.to_string())
    }

    pub(crate) fn resume_session_effect(&mut self, resume: ResumeSession) {
        if let Some(run_id) = normalized_resume_run_id(resume) {
            self.open_resume_replay(run_id);
            return;
        }
        if self.resume_paused_scan() {
            return;
        }
        self.show_resume_guidance();
    }

    fn open_resume_replay(&mut self, run_id: String) {
        self.router.replay_mut().open(run_id.clone());
        self.shell_view = ShellView::Replay;
        self.log(
            "resume",
            format!(
                "checkpoint resume not implemented; opening replay {run_id}. Next: /replay {run_id}"
            ),
        );
    }

    fn resume_paused_scan(&mut self) -> bool {
        if !self.is_scan_paused() {
            return false;
        }
        if let Some(cancel) = self.scan_cancel_token() {
            cancel.resume();
        }
        self.set_scan_stage("running");
        self.log("resume", "scan resumed");
        true
    }

    fn show_resume_guidance(&mut self) {
        self.shell_view = ShellView::Runs;
        self.log(
            "resume",
            "no paused scan to resume. Next: show runs, replay <runId>, or scan <target>",
        );
    }

    pub fn is_scan_paused(&self) -> bool {
        self.scan_cancel_token()
            .map(|cancel| cancel.is_paused())
            .unwrap_or(false)
    }

    pub(crate) fn running_tool_name(&self) -> Option<&str> {
        self.tool_run.active_name()
    }

    pub(crate) fn tool_abort_requested(&self) -> bool {
        self.tool_run.abort_requested()
    }

    #[cfg(test)]
    pub(crate) fn set_running_tool_for_test(&mut self, tool_name: &str) {
        self.tool_run
            .set_running_for_test(Some(tool_name.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn clear_running_tool_for_test(&mut self) {
        self.tool_run.set_running_for_test(None);
    }

    #[cfg(test)]
    pub(crate) fn set_tool_cancel_for_test(&mut self, cancel: ScanCancellation) {
        self.tool_run.set_cancel_for_test(Some(cancel));
    }

    #[cfg(test)]
    pub(crate) fn set_active_tool_run_id_for_test(&mut self, run_id: &str) {
        self.tool_run.set_run_id_for_test(Some(run_id.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn set_tool_abort_requested_for_test(&mut self, requested: bool) {
        self.tool_run.set_abort_requested_for_test(requested);
    }

    #[cfg(test)]
    pub(crate) fn set_ambient_tool_for_test(&mut self, tool_name: &str) {
        self.tool_run
            .set_ambient_for_test(Some(tool_name.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn set_active_model_override_for_test(&mut self, model: &str) {
        self.set_active_model_override(Some(model.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn set_scan_cancel_for_test(&mut self, cancel: ScanCancellation) {
        self.set_scan_cancel(Some(cancel));
    }

    pub(crate) fn pause_active_work_effect(&mut self) {
        if self.pause_running_scan() {
            return;
        }
        if self.log_agent_chat_pause_absent() {
            return;
        }
        self.log_pause_unavailable();
    }

    fn pause_running_scan(&mut self) -> bool {
        if !self.scan().is_some_and(|scan| scan.running) {
            return false;
        }
        let Some(cancel) = self.scan_cancel_token() else {
            return false;
        };
        cancel.pause();
        self.set_scan_stage("paused");
        self.log(
            "pause",
            "scan paused; in-flight scanner may finish its current step. Resume with /resume",
        );
        true
    }

    fn log_agent_chat_pause_absent(&mut self) -> bool {
        if !self.agent_chat().is_some_and(|agent| agent.running) {
            return false;
        }
        self.log(
            "pause",
            "pause is intentionally absent for Rust agent chat. Wait for the answer or start a new question after it finishes.",
        );
        true
    }

    fn log_pause_unavailable(&mut self) {
        self.log(
            "pause",
            "no live pause/resume control is active in the Rust shell. Next: scan <target> or run <tool>",
        );
    }

    fn set_scan_stage(&mut self, stage: &str) {
        if let Some(scan) = self.scan_mut() {
            scan.stage = stage.to_string();
        }
    }
}

fn normalized_load_specifier(specifier: Option<String>) -> Option<String> {
    specifier
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalized_resume_run_id(resume: ResumeSession) -> Option<String> {
    resume.run_id.filter(|value| !value.trim().is_empty())
}
