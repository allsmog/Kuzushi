use super::*;
#[cfg(test)]
use kuzushi_core::ScanCancellation;

impl ShellApp {
    pub(crate) fn handle_load_command(&mut self, specifier: Option<String>) {
        self.shell_view = ShellView::Tools;
        let Some(specifier) = specifier
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            self.log(
                "error",
                "load requires a module specifier. Next: load builtin:sast or modules",
            );
            return;
        };

        let module_id = specifier
            .strip_prefix("builtin:")
            .unwrap_or(specifier.as_str())
            .trim();
        if !module_id.contains(':')
            && self
                .registry
                .modules()
                .any(|module| module.metadata().id == module_id)
        {
            self.log(
                "load",
                format!(
                    "{specifier} is already available in the Rust static registry. Next: use {module_id}"
                ),
            );
            return;
        }

        self.log(
            "error",
            format!(
                "dynamic module loading is not supported by the Rust shell; {specifier:?} was not loaded. Next: modules"
            ),
        );
    }

    pub(crate) fn handle_resume_command(&mut self, run_id: Option<String>) {
        if let Some(run_id) = run_id.filter(|value| !value.trim().is_empty()) {
            self.shell_view = ShellView::Replay(run_id.clone());
            self.log(
                "resume",
                format!(
                    "checkpoint resume not implemented; opening replay {run_id}. Next: /replay {run_id}"
                ),
            );
            return;
        }
        if self.is_scan_paused() {
            if let Some(cancel) = &self.scan_cancel {
                cancel.resume();
            }
            if let Some(scan) = &mut self.scan {
                scan.stage = "running".to_string();
            }
            self.log("resume", "scan resumed");
            return;
        }
        self.shell_view = ShellView::Runs;
        self.log(
            "resume",
            "no paused scan to resume. Next: show runs, replay <runId>, or scan <target>",
        );
    }

    pub fn is_scan_paused(&self) -> bool {
        self.scan_cancel
            .as_ref()
            .map(|cancel| cancel.is_paused())
            .unwrap_or(false)
    }

    pub(crate) fn running_tool_name(&self) -> Option<&str> {
        self.tool_running.as_deref()
    }

    pub(crate) fn tool_abort_requested(&self) -> bool {
        self.tool_abort_requested
    }

    #[cfg(test)]
    pub(crate) fn set_running_tool_for_test(&mut self, tool_name: &str) {
        self.tool_running = Some(tool_name.to_string());
    }

    #[cfg(test)]
    pub(crate) fn set_scan_cancel_for_test(&mut self, cancel: ScanCancellation) {
        self.scan_cancel = Some(cancel);
    }

    pub(crate) fn handle_pause_command(&mut self) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            if let Some(cancel) = &self.scan_cancel {
                cancel.pause();
                if let Some(scan) = &mut self.scan {
                    scan.stage = "paused".to_string();
                }
                self.log(
                    "pause",
                    "scan paused; in-flight scanner may finish its current step. Resume with /resume",
                );
                return;
            }
        }
        if self.agent_chat.as_ref().is_some_and(|agent| agent.running) {
            self.log(
                "pause",
                "pause is intentionally absent for Rust agent chat. Wait for the answer or start a new question after it finishes.",
            );
            return;
        }
        self.log(
            "pause",
            "no live pause/resume control is active in the Rust shell. Next: scan <target> or run <tool>",
        );
    }
}
