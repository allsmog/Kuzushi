use std::path::PathBuf;

#[cfg(test)]
use kuzushi_core::ScanCancellation;
use kuzushi_core::WorkspaceTarget;

use crate::commands::{ContextCommand, WorkspaceCommand};

use super::{ShellApp, ShellView};

impl ShellApp {
    pub(super) fn handle_context_command(&mut self, command: ContextCommand) {
        match command {
            ContextCommand::Show | ContextCommand::Status => self.show_context_status(),
            ContextCommand::Build => self.build_context_snapshot(None),
            ContextCommand::Regen(slice) => self.regen_context_slice(&slice),
        }
    }

    pub(super) fn handle_workspace_command(&mut self, command: WorkspaceCommand) {
        match command {
            WorkspaceCommand::Status => self.show_workspace_status(),
            WorkspaceCommand::ExportFindings { output } => self.export_workspace_findings(&output),
            WorkspaceCommand::Unsupported(raw) => {
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!(
                        "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace export findings <path>.json"
                    ),
                );
            }
        }
    }

    pub(super) fn show_history(&mut self) {
        self.shell_view = ShellView::History;
        self.history_scroll = 0;
        self.log(
            "history",
            format!(
                "showing {} command(s). Next: clear or run <tool>",
                self.command_history.len()
            ),
        );
    }

    pub(crate) fn clear_conversation(&mut self) {
        self.log.clear();
        self.selected_finding = None;
        self.agent_chat = None;
        self.agent_rx = None;
        self.shell_view = ShellView::Catalog;
        self.log(
            "system",
            "Conversation cleared. Command history retained. Next: history or help",
        );
    }

    pub(super) fn handle_load_command(&mut self, specifier: Option<String>) {
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

    pub(super) fn handle_resume_command(&mut self, run_id: Option<String>) {
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

    pub(super) fn handle_pause_command(&mut self) {
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

    pub fn show_quickstart(&mut self) {
        self.shell_view = ShellView::Quickstart;
        // Two log lines (not eight) for the operator-facing transcript.
        // The full guide is rendered in the Quickstart view, which gets the
        // full body area instead of the 2-row transcript strip.
        let scan_command = self.first_finding_scan_command();
        self.log(
            "quickstart",
            format!("Exact first-finding path: {scan_command} -> findings"),
        );
    }

    pub fn handle_target_command(&mut self, raw: Option<&str>) {
        let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
            let current = self
                .target
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unset>".to_string());
            self.log("target", format!("current target: {current}"));
            return;
        };
        let path = PathBuf::from(raw);
        match WorkspaceTarget::new(&path) {
            Ok(workspace) => {
                let root = workspace.root().to_path_buf();
                self.target = Some(root.clone());
                if let Err(error) = workspace.ensure_state_dir() {
                    self.log(
                        "target",
                        format!("set {} but state dir init failed: {error}", root.display()),
                    );
                } else {
                    self.log("target", format!("set {}", root.display()));
                }
                self.refresh_findings(false);
            }
            Err(error) => self.log("error", format!("invalid target {raw:?}: {error}")),
        }
    }

    pub(super) fn show_story(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            return;
        }
        self.story_return_view = Some(self.shell_view.clone());
        self.shell_view = ShellView::Story;
    }

    pub fn toggle_story_overlay(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            if let Some(previous) = self.story_return_view.take() {
                self.shell_view = previous;
            } else {
                self.shell_view = ShellView::Catalog;
            }
        } else {
            self.show_story();
        }
    }
}
