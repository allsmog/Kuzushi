use super::*;

impl ShellApp {
    pub(crate) fn prompt_edit(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt edit requires a focused module and a workspace target. Next: /use <module>, then prompt edit <name>",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        if !path.exists() {
            if let Err(error) = std::fs::write(&path, "") {
                self.log(
                    "error",
                    format!("could not seed {}: {error}", path.display()),
                );
                return;
            }
        }
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "${EDITOR}".to_string());
        self.log(
            "prompt",
            format!(
                "edit override at {}; suspend the shell and run `{editor} {0}` (Ctrl+C twice to exit when done)",
                path.display()
            ),
        );
    }

    pub(crate) fn prompt_show(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt show requires a focused module and workspace. Next: /use <module>",
            );
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => {
                self.log(
                    "prompt",
                    format!("override {} is empty (using default)", path.display()),
                );
            }
            Ok(text) => {
                self.log(
                    "prompt",
                    format!("override {} ({} bytes):", path.display(), text.len()),
                );
                for line in text.lines().take(40) {
                    self.log("prompt", line.to_string());
                }
            }
            Err(_) => {
                self.log(
                    "prompt",
                    format!("no override at {}; using built-in default", path.display()),
                );
            }
        }
    }
}
