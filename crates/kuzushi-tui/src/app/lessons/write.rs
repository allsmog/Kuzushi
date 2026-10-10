use super::*;

impl ShellApp {
    pub(super) fn submit_lesson_form(&mut self) {
        let Some(form) = self.router.lessons.form.as_ref() else {
            return;
        };
        if self.target() != Some(form.target.as_path()) {
            self.router.lessons.notice =
                Some("Target changed. Return to the recorded target before saving.".into());
            return;
        }
        match form::lesson_form_input(form) {
            Ok((name, input)) => self.spawn_lesson_action(name, input),
            Err(error) => self.router.lessons.notice = Some(error.to_string()),
        }
    }

    pub(super) fn spawn_lesson_action(&mut self, name: &'static str, input: serde_json::Value) {
        if self.runtime_state.lesson_write.is_some() {
            return;
        }
        let Some(target) = self.target_owned() else {
            return;
        };
        let worker_target = target.clone();
        let config = self.config().clone();
        let handle = std::thread::spawn(move || {
            let workspace = kuzushi_core::WorkspaceTarget::new(worker_target)
                .map_err(|error| error.to_string())?;
            kuzushi_core::workspace::execute_lesson_action(&workspace, &config, name, input)
                .map_err(|error| format!("{error:#}"))
        });
        self.runtime_state.lesson_write = Some(LessonWrite {
            target,
            action: name,
            handle,
        });
        self.router.lessons.notice =
            Some("Saving the reviewed action. Waiting for its durable receipt.".into());
    }

    pub(crate) fn poll_lesson_write(&mut self) -> bool {
        let Some(pending) = self.runtime_state.lesson_write.as_ref() else {
            return false;
        };
        if !pending.handle.is_finished() {
            return false;
        }
        let pending = self.runtime_state.lesson_write.take().unwrap();
        let result = pending
            .handle
            .join()
            .unwrap_or_else(|_| Err("Lesson writer stopped unexpectedly".into()));
        if self.target() != Some(pending.target.as_path()) {
            self.set_info_notice(
                "lessons",
                "Lesson write finished for the earlier target. Inspect its recorded state.",
            );
            return true;
        }
        self.finish_lesson_action(pending.action, result);
        true
    }

    fn finish_lesson_action(&mut self, action: &str, result: Result<serde_json::Value, String>) {
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                self.router.lessons.notice=Some(format!("Lesson action not confirmed: {error}. Draft retained. Inspect recorded state before retrying."));
                return;
            }
        };
        self.refresh_lessons();
        self.router.lessons.form_visible = false;
        self.router.lessons.form = None;
        if action == "threat-model:reuse-lessons" {
            self.finish_lesson_context(&output);
            return;
        }
        self.router.lessons.notice = Some(
            output["output"]
                .as_str()
                .unwrap_or("Lesson action saved. Refresh to inspect its exact revision.")
                .into(),
        );
        self.router.lessons.selected.clear();
    }
}
