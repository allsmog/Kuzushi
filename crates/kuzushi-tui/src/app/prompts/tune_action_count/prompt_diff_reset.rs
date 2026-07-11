use super::*;

impl ShellApp {
    pub(crate) fn reduce_prompt_diff(&mut self, name: &str) -> Vec<ShellEffect> {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt diff requires a focused module and workspace",
            );
            return Vec::new();
        };
        vec![ShellEffect::DiffPromptOverride(PromptOverrideDiff { path })]
    }

    pub(crate) fn diff_prompt_override_effect(&mut self, diff: PromptOverrideDiff) {
        let Some(target) = self.target_owned() else {
            self.log("error", "could not diff prompt override without a target");
            return;
        };
        match prompt_override_path_state(&target, &diff.path) {
            PromptOverridePathState::File => self.log(
                "prompt",
                format!("diff candidate: git diff -- {}", diff.path.display()),
            ),
            PromptOverridePathState::Missing => self.log(
                "prompt",
                format!("no override file to diff at {}", diff.path.display()),
            ),
            PromptOverridePathState::Unreadable => self.log(
                "prompt",
                format!(
                    "could not diff unreadable override at {}",
                    diff.path.display()
                ),
            ),
        }
    }

    pub(crate) fn reduce_prompt_reset(&mut self, name: &str) -> Vec<ShellEffect> {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt reset requires a focused module and workspace",
            );
            return Vec::new();
        };
        vec![ShellEffect::ResetPromptOverride(PromptOverrideReset {
            path,
        })]
    }

    pub(crate) fn reset_prompt_override_effect(&mut self, reset: PromptOverrideReset) {
        let Some(target) = self.target_owned() else {
            self.log("error", "could not reset prompt override without a target");
            return;
        };
        match prompt_override_path_state(&target, &reset.path) {
            PromptOverridePathState::File => self.remove_prompt_override(&target, &reset.path),
            PromptOverridePathState::Missing => self.log(
                "prompt",
                format!("no override at {} to reset", reset.path.display()),
            ),
            PromptOverridePathState::Unreadable => self.log(
                "prompt",
                format!(
                    "could not reset unreadable override at {}",
                    reset.path.display()
                ),
            ),
        }
    }

    fn remove_prompt_override(&mut self, target: &std::path::Path, path: &std::path::Path) {
        if !matches!(
            prompt_override_path_state(target, path),
            PromptOverridePathState::File
        ) {
            self.log(
                "error",
                format!("prompt override changed before reset: {}", path.display()),
            );
            return;
        }
        let relative = match path.strip_prefix(target) {
            Ok(relative) => relative,
            Err(_) => {
                self.log("error", "prompt override path escaped the active target");
                return;
            }
        };
        match kuzushi_core::workspace::remove_workspace_state_file(target, relative) {
            Ok(true) => self.log("prompt", format!("removed override {}", path.display())),
            Ok(false) => self.log(
                "prompt",
                format!("no override at {} to reset", path.display()),
            ),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }
}

enum PromptOverridePathState {
    File,
    Missing,
    Unreadable,
}

fn prompt_override_path_state(
    target: &std::path::Path,
    path: &std::path::Path,
) -> PromptOverridePathState {
    match kuzushi_core::workspace::read_optional_workspace_text(target, path, 1024 * 1024) {
        Ok(Some(_)) => PromptOverridePathState::File,
        Ok(None) => PromptOverridePathState::Missing,
        Err(_) => PromptOverridePathState::Unreadable,
    }
}
