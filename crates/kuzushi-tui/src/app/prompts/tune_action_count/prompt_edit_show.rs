use super::*;

impl ShellApp {
    pub(crate) fn reduce_prompt_edit(&mut self, name: &str) -> Vec<ShellEffect> {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt edit requires a focused module and a workspace target. Next: /use <module>, then prompt edit <name>",
            );
            return Vec::new();
        };
        vec![ShellEffect::EditPromptOverride(PromptOverrideEdit { path })]
    }

    pub(crate) fn edit_prompt_override_effect(&mut self, edit: PromptOverrideEdit) {
        if !self.ensure_prompt_edit_parent(&edit.path) {
            return;
        }
        if !self.ensure_prompt_override_editable(&edit.path) {
            return;
        }
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "${EDITOR}".to_string());
        self.log(
            "prompt",
            format!(
                "edit override at {}; suspend the shell and run `{editor} {0}` (Ctrl+C twice to exit when done)",
                edit.path.display()
            ),
        );
    }

    fn ensure_prompt_edit_parent(&mut self, path: &std::path::Path) -> bool {
        let Some(parent) = path.parent() else {
            return true;
        };
        match std::fs::create_dir_all(parent) {
            Ok(_) => true,
            Err(error) => {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                false
            }
        }
    }

    fn ensure_prompt_override_editable(&mut self, path: &std::path::Path) -> bool {
        match prompt_edit_path_state(path) {
            PromptEditPathState::File => true,
            PromptEditPathState::Missing => self.seed_prompt_override(path),
            PromptEditPathState::Unreadable => {
                self.log(
                    "prompt",
                    format!("could not edit unreadable override at {}", path.display()),
                );
                false
            }
        }
    }

    fn seed_prompt_override(&mut self, path: &std::path::Path) -> bool {
        match std::fs::write(path, "") {
            Ok(_) => true,
            Err(error) => {
                self.log(
                    "error",
                    format!("could not seed {}: {error}", path.display()),
                );
                false
            }
        }
    }

    pub(crate) fn reduce_prompt_show(&mut self, name: &str) -> Vec<ShellEffect> {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt show requires a focused module and workspace. Next: /use <module>",
            );
            return Vec::new();
        };
        vec![ShellEffect::ShowPromptOverride(PromptOverrideShow { path })]
    }

    pub(crate) fn show_prompt_override_effect(&mut self, show: PromptOverrideShow) {
        match prompt_override_text(&show.path) {
            PromptOverrideText::Missing => self.log_missing_prompt_override(&show.path),
            PromptOverrideText::Empty => self.log_empty_prompt_override(&show.path),
            PromptOverrideText::Present(text) => {
                self.log_prompt_override_text(&show.path, &text);
            }
            PromptOverrideText::Unreadable => self.log_unreadable_prompt_override(&show.path),
        }
    }

    fn log_missing_prompt_override(&mut self, path: &std::path::Path) {
        self.log(
            "prompt",
            format!("no override at {}; using built-in default", path.display()),
        );
    }

    fn log_empty_prompt_override(&mut self, path: &std::path::Path) {
        self.log(
            "prompt",
            format!("override {} is empty (using default)", path.display()),
        );
    }

    fn log_prompt_override_text(&mut self, path: &std::path::Path, text: &str) {
        self.log(
            "prompt",
            format!("override {} ({} bytes):", path.display(), text.len()),
        );
        for line in text.lines().take(40) {
            self.log("prompt", line.to_string());
        }
    }

    fn log_unreadable_prompt_override(&mut self, path: &std::path::Path) {
        self.log(
            "prompt",
            format!("could not read override at {}", path.display()),
        );
    }
}

enum PromptOverrideText {
    Missing,
    Empty,
    Present(String),
    Unreadable,
}

fn prompt_override_text(path: &std::path::Path) -> PromptOverrideText {
    if !path.exists() {
        return PromptOverrideText::Missing;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => prompt_override_text_from_string(text),
        Err(_) => PromptOverrideText::Unreadable,
    }
}

fn prompt_override_text_from_string(text: String) -> PromptOverrideText {
    if text.trim().is_empty() {
        PromptOverrideText::Empty
    } else {
        PromptOverrideText::Present(text)
    }
}

enum PromptEditPathState {
    File,
    Missing,
    Unreadable,
}

fn prompt_edit_path_state(path: &std::path::Path) -> PromptEditPathState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => PromptEditPathState::File,
        Ok(_) => PromptEditPathState::Unreadable,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PromptEditPathState::Missing,
        Err(_) => PromptEditPathState::Unreadable,
    }
}
