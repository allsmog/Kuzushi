use super::*;
use anyhow::Context as _;
#[cfg(test)]
use kuzushi_core::ScanCancellation;

impl ShellApp {
    pub(crate) fn reduce_load_command(&mut self, specifier: Option<String>) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Tools);
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

    pub(crate) fn resume_session_effect(&mut self, resume: ResumeSession) -> Vec<ShellEffect> {
        if let Some(run_id) = normalized_resume_run_id(resume) {
            return self.resume_recorded_run(run_id);
        }
        if !self.resume_paused_scan() {
            self.offer_latest_resumable_run();
        }
        Vec::new()
    }

    /// Bare `resume` with nothing paused: draft `resume <runId>` for the most
    /// recent resumable run so one Enter continues it — the operator commits
    /// the spend explicitly instead of the shell auto-dispatching.
    fn offer_latest_resumable_run(&mut self) {
        let Some(run_id) = self.latest_resumable_run_id() else {
            self.show_resume_guidance();
            return;
        };
        self.log(
            "resume",
            format!("latest resumable run is {run_id} — Enter re-dispatches it"),
        );
        self.set_input(format!("resume {run_id}"));
        self.set_input_mode(InputMode::Prompt);
    }

    fn latest_resumable_run_id(&self) -> Option<String> {
        let target = self.target()?;
        kuzushi_core::list_run_summaries(target)
            .ok()?
            .into_iter()
            .find(|summary| {
                matches!(
                    summary.status.as_str(),
                    "failed" | "interrupted" | "canceled"
                ) && summary.tool.is_some()
            })
            .map(|summary| summary.run_id)
    }

    /// `resume <runId>`: re-dispatch the failed run's recorded tool + input.
    /// Agent tool loops pick up their transcript checkpoint automatically, so
    /// this continues from the failure point instead of re-buying completed
    /// turns. Runs without a resumable invocation fall back to replay.
    fn resume_recorded_run(&mut self, run_id: String) -> Vec<ShellEffect> {
        match self.resumable_run_invocation(&run_id) {
            Ok(Some((tool, input))) => {
                self.log(
                    "resume",
                    format!(
                        "resuming {run_id} — re-dispatching {tool}; completed agent turns replay from the checkpoint"
                    ),
                );
                self.reduce_run_tool(Some(tool), Some(input))
            }
            Ok(None) => {
                self.open_resume_replay(run_id);
                Vec::new()
            }
            Err(error) => {
                self.log("error", format!("resume: {error:#}"));
                self.open_resume_replay(run_id);
                Vec::new()
            }
        }
    }

    /// A run can be resumed when it ended without completing (failed,
    /// interrupted, or canceled) and recorded the tool + input it was
    /// dispatched with. Anything else is inspect-only.
    fn resumable_run_invocation(
        &mut self,
        run_id: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let Some(target) = self.target_owned() else {
            anyhow::bail!("resume requires an active target. Next: target <path>");
        };
        let summary = kuzushi_core::run_artifacts::load_run_summary(&target, run_id)?;
        let resumable = matches!(
            summary.status.as_str(),
            "failed" | "interrupted" | "canceled"
        );
        let Some(tool) = summary.tool.filter(|_| resumable) else {
            return Ok(None);
        };
        let input_path = kuzushi_core::run_artifacts::run_dir(&target, run_id).join("input.json");
        let input = std::fs::read_to_string(&input_path)
            .with_context(|| format!("Could not read recorded input {}", input_path.display()))?;
        Ok(Some((tool, input)))
    }

    fn open_resume_replay(&mut self, run_id: String) {
        self.router.replay_mut().open(run_id.clone());
        self.set_shell_view(ShellView::Replay);
        self.log(
            "resume",
            format!(
                "run is not resumable (only failed/interrupted/canceled tool runs are); opening replay {run_id}. Next: /replay {run_id}"
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
        self.set_shell_view(ShellView::Runs);
        self.log(
            "resume",
            "nothing to resume — no paused scan and no failed/interrupted run. Next: show runs, replay <runId>, or scan <target>",
        );
    }

    pub fn is_scan_paused(&self) -> bool {
        self.scan_cancel_token()
            .map(|cancel| cancel.is_paused())
            .unwrap_or(false)
    }

    pub(crate) fn running_tool_name(&self) -> Option<&str> {
        self.runtime_state.tool_run().active_name()
    }

    pub(crate) fn tool_abort_requested(&self) -> bool {
        self.runtime_state.tool_run().abort_requested()
    }

    #[cfg(test)]
    pub(crate) fn set_running_tool_for_test(&mut self, tool_name: &str) {
        self.runtime_state
            .tool_run_mut()
            .set_running_for_test(Some(tool_name.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn clear_running_tool_for_test(&mut self) {
        self.runtime_state.tool_run_mut().set_running_for_test(None);
    }

    #[cfg(test)]
    pub(crate) fn set_tool_cancel_for_test(&mut self, cancel: ScanCancellation) {
        self.runtime_state
            .tool_run_mut()
            .set_cancel_for_test(Some(cancel));
    }

    #[cfg(test)]
    pub(crate) fn set_active_tool_run_id_for_test(&mut self, run_id: &str) {
        let target = self.target_owned();
        let changed = self.active_tool_run_id() != Some(run_id);
        self.runtime_state
            .tool_run_mut()
            .set_run_id_for_test(Some(run_id.to_string()));
        self.runtime_state
            .tool_run_mut()
            .set_target_for_test(target);
        self.bump_completion_generation_when(changed);
    }

    #[cfg(test)]
    pub(crate) fn set_tool_abort_requested_for_test(&mut self, requested: bool) {
        self.runtime_state
            .tool_run_mut()
            .set_abort_requested_for_test(requested);
    }

    #[cfg(test)]
    pub(crate) fn set_ambient_tool_for_test(&mut self, tool_name: &str) {
        self.runtime_state
            .tool_run_mut()
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

#[cfg(test)]
mod resume_tests {
    use super::*;
    use kuzushi_core::{V2Config, WorkspaceTarget};

    fn app_with_run(status_failed: bool) -> (tempfile::TempDir, ShellApp, String) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let run_id = "run-resume-1".to_string();
        let summary = kuzushi_core::RunSummary::running(
            run_id.clone(),
            "tool",
            Some("x-ray:run".to_string()),
            workspace.root().display().to_string(),
        );
        let summary = if status_failed {
            summary.failed("LangGraph bridge failed: Provider rate limited the request (HTTP 429).")
        } else {
            summary
        };
        kuzushi_core::write_run_summary(workspace.root(), &summary).unwrap();
        let run_dir = kuzushi_core::run_artifacts::run_dir(workspace.root(), &run_id);
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::write(run_dir.join("input.json"), r#"{"target":"."}"#).unwrap();
        let app = ShellApp::new(V2Config::default(), Some(&workspace));
        (temp, app, run_id)
    }

    #[test]
    fn failed_run_resumes_with_its_recorded_tool_and_input() {
        let (_temp, mut app, run_id) = app_with_run(true);

        let invocation = app.resumable_run_invocation(&run_id).unwrap();

        assert_eq!(
            invocation,
            Some(("x-ray:run".to_string(), r#"{"target":"."}"#.to_string()))
        );
    }

    #[test]
    fn bare_resume_drafts_the_latest_resumable_run() {
        let (_temp, mut app, run_id) = app_with_run(true);

        let effects = app.resume_session_effect(ResumeSession { run_id: None });

        assert!(effects.is_empty());
        assert_eq!(app.input(), format!("resume {run_id}"));
        assert_eq!(app.input_mode(), InputMode::Prompt);
    }

    #[test]
    fn still_running_run_is_not_resumable_and_falls_back_to_replay() {
        let (_temp, mut app, run_id) = app_with_run(false);

        assert_eq!(app.resumable_run_invocation(&run_id).unwrap(), None);

        let effects = app.resume_session_effect(ResumeSession {
            run_id: Some(run_id.clone()),
        });
        assert!(effects.is_empty());
        assert_eq!(app.shell_view(), ShellView::Replay);
    }
}
