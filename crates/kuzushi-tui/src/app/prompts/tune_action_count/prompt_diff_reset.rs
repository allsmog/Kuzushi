use super::*;

impl ShellApp {
    pub(crate) fn prompt_diff(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt diff requires a focused module and workspace",
            );
            return;
        };
        match prompt_override_path_state(&path) {
            PromptOverridePathState::File => self.log(
                "prompt",
                format!("diff candidate: git diff -- {}", path.display()),
            ),
            PromptOverridePathState::Missing => self.log(
                "prompt",
                format!("no override file to diff at {}", path.display()),
            ),
            PromptOverridePathState::Unreadable => self.log(
                "prompt",
                format!("could not diff unreadable override at {}", path.display()),
            ),
        }
    }

    pub(crate) fn prompt_reset(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt reset requires a focused module and workspace",
            );
            return;
        };
        match prompt_override_path_state(&path) {
            PromptOverridePathState::File => self.remove_prompt_override(&path),
            PromptOverridePathState::Missing => self.log(
                "prompt",
                format!("no override at {} to reset", path.display()),
            ),
            PromptOverridePathState::Unreadable => self.log(
                "prompt",
                format!("could not reset unreadable override at {}", path.display()),
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
