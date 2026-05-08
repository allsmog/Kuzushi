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
        if path.exists() {
            self.log(
                "prompt",
                format!("diff candidate: git diff -- {}", path.display()),
            );
        } else {
            self.log(
                "prompt",
                format!("no override file to diff at {}", path.display()),
            );
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
        if !path.exists() {
            self.log(
                "prompt",
                format!("no override at {} to reset", path.display()),
            );
            return;
        }
        match std::fs::remove_file(&path) {
            Ok(_) => self.log("prompt", format!("removed override {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }
}
