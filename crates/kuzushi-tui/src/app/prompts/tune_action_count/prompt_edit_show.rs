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
        self.open_selected_prompt_document(edit.path);
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
        if self.selected_prompt_spec().is_some() {
            self.open_selected_prompt_document(show.path);
            return;
        }
        let Some(target) = self.target_path_buf().cloned() else {
            self.log("error", "could not show prompt override without a target");
            return;
        };
        match prompt_override_text(&target, &show.path) {
            PromptOverrideText::Missing => self.log_missing_prompt_override(&show.path),
            PromptOverrideText::Empty => self.log_empty_prompt_override(&show.path),
            PromptOverrideText::Present(text) => {
                self.log_prompt_override_text(&show.path, &text);
            }
            PromptOverrideText::Unreadable => self.log_unreadable_prompt_override(&show.path),
        }
    }

    fn selected_prompt_spec(&self) -> Option<kuzushi_core::modules::PromptSpec> {
        let module = self.focused_module()?;
        let verb = self.current_prompt_verb_name()?;
        self.prompt_spec_for_tool(&format!("{module}:{verb}"))
    }

    fn open_selected_prompt_document(&mut self, path: std::path::PathBuf) {
        let Some(prompt) = self.selected_prompt_spec() else {
            self.log(
                "prompt",
                format!(
                    "no editable built-in template is declared for {}; select a model-backed tool",
                    path.display()
                ),
            );
            return;
        };
        let origin = self.shell_view();
        self.open_prompt_document_effect(PromptDocumentOpen { prompt, origin });
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

fn prompt_override_text(target: &std::path::Path, path: &std::path::Path) -> PromptOverrideText {
    match kuzushi_core::workspace::read_optional_workspace_text(target, path, 1024 * 1024) {
        Ok(Some(text)) => prompt_override_text_from_string(text),
        Ok(None) => PromptOverrideText::Missing,
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
