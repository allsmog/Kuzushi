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
        match prompt_override_path_state(&diff.path) {
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
        match prompt_override_path_state(&reset.path) {
            PromptOverridePathState::File => self.remove_prompt_override(&reset.path),
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

    fn remove_prompt_override(&mut self, path: &std::path::Path) {
        match std::fs::remove_file(path) {
            Ok(_) => self.log("prompt", format!("removed override {}", path.display())),
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

fn prompt_override_path_state(path: &std::path::Path) -> PromptOverridePathState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => PromptOverridePathState::File,
        Ok(_) => PromptOverridePathState::Unreadable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PromptOverridePathState::Missing
        }
        Err(_) => PromptOverridePathState::Unreadable,
    }
}
