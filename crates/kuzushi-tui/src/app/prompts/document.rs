use super::*;
use crate::app::state_transitions::InputUpdate;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::modules::{PromptSpec, RuntimeRequirement};

mod buffer_edit;

const PROMPT_DOCUMENT_LIMIT: usize = 1024 * 1024;
const PAGE_ROWS: usize = 20;

impl ShellApp {
    pub(crate) fn prompt_spec_for_tool(&self, tool_name: &str) -> Option<PromptSpec> {
        self.registry()
            .resolve_tool(tool_name)
            .filter(|tool| tool.runtime_requirement != RuntimeRequirement::Never)
            .and_then(|tool| tool.prompts.first())
            .cloned()
    }

    pub(crate) fn planning_prompt_review_available(&self) -> bool {
        self.selected_planning_prompt().is_some()
    }

    pub(crate) fn review_planning_prompt(&mut self) -> Vec<ShellEffect> {
        let Some(prompt) = self.selected_planning_prompt() else {
            self.log(
                "prompt",
                "select a model-backed step with an editable prompt before reviewing",
            );
            return Vec::new();
        };
        vec![ShellEffect::OpenPromptDocument(PromptDocumentOpen {
            prompt,
            origin: ShellView::PlanningPicker,
        })]
    }

    fn selected_planning_prompt(&self) -> Option<PromptSpec> {
        let picker = self.engagement.planning_picker();
        let current = picker
            .current_row()
            .filter(|row| picker.selected().contains(&row.id));
        current
            .and_then(|row| self.prompt_spec_for_tool(row.tool_name))
            .or_else(|| {
                picker
                    .tasks()
                    .iter()
                    .filter(|row| picker.selected().contains(&row.id))
                    .find_map(|row| self.prompt_spec_for_tool(row.tool_name))
            })
    }

    pub(crate) fn open_prompt_document_effect(&mut self, open: PromptDocumentOpen) {
        let Some(target) = self.target_owned() else {
            self.log(
                "prompt",
                "prompt review requires an active workspace target",
            );
            return;
        };
        let document = match load_prompt_document(&target, open.prompt, open.origin) {
            Ok(document) => document,
            Err(error) => {
                self.log("prompt", format!("could not open prompt review: {error}"));
                return;
            }
        };
        self.router.prompts_mut().open_document(document);
        self.set_shell_view(ShellView::PromptsEditor);
    }

    pub(crate) fn reduce_prompt_document_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return InputUpdate::ignored();
        }
        let Some(mode) = self
            .router
            .prompts()
            .document()
            .map(|document| document.mode)
        else {
            return InputUpdate::ignored();
        };
        match mode {
            PromptDocumentMode::Normal => self.reduce_prompt_normal_key(key),
            PromptDocumentMode::Insert => self.reduce_prompt_insert_key(key),
            PromptDocumentMode::Command => self.reduce_prompt_command_key(key),
            PromptDocumentMode::ConfirmDiscard => self.reduce_prompt_discard_key(key),
        }
    }

    fn reduce_prompt_normal_key(&mut self, key: KeyEvent) -> InputUpdate {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('i') if !ctrl => {
                self.set_prompt_document_mode(PromptDocumentMode::Insert)
            }
            KeyCode::Char(':') if !ctrl => self.begin_prompt_document_command(),
            KeyCode::Down | KeyCode::Char('j') if !ctrl => self.move_prompt_document_row(1),
            KeyCode::Up | KeyCode::Char('k') if !ctrl => self.move_prompt_document_row(-1),
            KeyCode::PageDown | KeyCode::Char('f') if ctrl => {
                self.move_prompt_document_row(PAGE_ROWS as isize)
            }
            KeyCode::PageUp | KeyCode::Char('b') if ctrl => {
                self.move_prompt_document_row(-(PAGE_ROWS as isize))
            }
            KeyCode::Char('G') if !ctrl => self.move_prompt_document_to_end(),
            KeyCode::Char('g') if !ctrl => self.handle_prompt_document_g(),
            KeyCode::Esc => self.request_prompt_document_close(),
            _ => self.clear_prompt_pending_g(),
        }
        InputUpdate::handled()
    }

    fn reduce_prompt_insert_key(&mut self, key: KeyEvent) -> InputUpdate {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => self.set_prompt_document_mode(PromptDocumentMode::Normal),
            KeyCode::Enter => self.insert_prompt_document_newline(),
            KeyCode::Backspace => self.backspace_prompt_document(),
            KeyCode::Left => self.move_prompt_document_col(-1),
            KeyCode::Right => self.move_prompt_document_col(1),
            KeyCode::Up => self.move_prompt_document_row(-1),
            KeyCode::Down => self.move_prompt_document_row(1),
            KeyCode::Char(ch) if !ctrl && !key.modifiers.contains(KeyModifiers::ALT) => {
                self.insert_prompt_document_char(ch)
            }
            _ => {}
        }
        InputUpdate::handled()
    }

    fn reduce_prompt_command_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Esc => self.cancel_prompt_document_command(),
            KeyCode::Backspace => self.backspace_prompt_document_command(),
            KeyCode::Enter => return self.execute_prompt_document_command(),
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                if let Some(document) = self.router.prompts_mut().document_mut() {
                    document.command.push(ch);
                }
            }
            _ => {}
        }
        InputUpdate::handled()
    }

    fn reduce_prompt_discard_key(&mut self, key: KeyEvent) -> InputUpdate {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => self.close_prompt_document(),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                self.set_prompt_document_mode(PromptDocumentMode::Normal)
            }
            _ => {}
        }
        InputUpdate::handled()
    }

    fn execute_prompt_document_command(&mut self) -> InputUpdate {
        let command = self
            .router
            .prompts()
            .document()
            .map(|document| document.command.trim().to_string())
            .unwrap_or_default();
        match command.as_str() {
            "w" => self.save_prompt_document(false),
            "wq" => self.save_prompt_document(true),
            "q" => {
                self.request_prompt_document_close();
                InputUpdate::handled()
            }
            "q!" => {
                self.close_prompt_document();
                InputUpdate::handled()
            }
            _ => {
                self.log("prompt", format!("unknown editor command :{command}"));
                self.cancel_prompt_document_command();
                InputUpdate::handled()
            }
        }
    }

    fn save_prompt_document(&mut self, exit_after_save: bool) -> InputUpdate {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return InputUpdate::handled();
        };
        document.mode = PromptDocumentMode::Normal;
        document.command.clear();
        document.exit_after_save = exit_after_save;
        InputUpdate::handled_with_effects(vec![ShellEffect::WritePromptOverride(
            PromptOverrideWrite {
                path: document.path.clone(),
                value: document.text(),
            },
        )])
    }

    pub(crate) fn finish_prompt_document_write(&mut self, path: &std::path::Path, value: &str) {
        let should_exit = {
            let Some(document) = self.router.prompts_mut().document_mut() else {
                return;
            };
            if document.path != path {
                return;
            }
            document.dirty = false;
            document.source = "repo override".to_string();
            document.hash = kuzushi_core::prompt_content_sha256(value);
            std::mem::take(&mut document.exit_after_save)
        };
        if should_exit {
            self.close_prompt_document();
        }
    }

    fn request_prompt_document_close(&mut self) {
        if self
            .router
            .prompts()
            .document()
            .is_some_and(|document| document.dirty)
        {
            self.set_prompt_document_mode(PromptDocumentMode::ConfirmDiscard);
        } else {
            self.close_prompt_document();
        }
    }

    fn close_prompt_document(&mut self) {
        let origin = self
            .router
            .prompts_mut()
            .close_document()
            .map(|document| document.origin)
            .unwrap_or(ShellView::Workbench);
        self.set_shell_view(origin);
    }

    fn set_prompt_document_mode(&mut self, mode: PromptDocumentMode) {
        if let Some(document) = self.router.prompts_mut().document_mut() {
            document.mode = mode;
            document.pending_g = false;
        }
    }

    fn begin_prompt_document_command(&mut self) {
        if let Some(document) = self.router.prompts_mut().document_mut() {
            document.mode = PromptDocumentMode::Command;
            document.command.clear();
        }
    }

    fn cancel_prompt_document_command(&mut self) {
        if let Some(document) = self.router.prompts_mut().document_mut() {
            document.mode = PromptDocumentMode::Normal;
            document.command.clear();
        }
    }

    fn backspace_prompt_document_command(&mut self) {
        let Some(document) = self.router.prompts_mut().document_mut() else {
            return;
        };
        if document.command.pop().is_none() {
            document.mode = PromptDocumentMode::Normal;
        }
    }
}

fn load_prompt_document(
    target: &std::path::Path,
    prompt: PromptSpec,
    origin: ShellView,
) -> anyhow::Result<PromptDocumentState> {
    let path = kuzushi_core::prompt_override_path(target, &prompt.module_id, &prompt.verb);
    let override_text = kuzushi_core::workspace::read_optional_workspace_text(
        target,
        &path,
        PROMPT_DOCUMENT_LIMIT,
    )?;
    let (text, source) = match override_text {
        Some(text) if !text.trim().is_empty() => (text, "repo override"),
        _ => (prompt.default_content, "built-in"),
    };
    let trailing_newline = text.ends_with('\n');
    Ok(PromptDocumentState {
        role: prompt.role,
        path,
        source: source.to_string(),
        hash: kuzushi_core::prompt_content_sha256(&text),
        context_note: prompt.context_note,
        lines: prompt_lines(text),
        trailing_newline,
        cursor_row: 0,
        cursor_col: 0,
        top_row: 0,
        mode: PromptDocumentMode::Normal,
        command: String::new(),
        dirty: false,
        exit_after_save: false,
        pending_g: false,
        origin,
    })
}

fn prompt_lines(text: String) -> Vec<String> {
    let lines = text.lines().map(ToString::to_string).collect::<Vec<_>>();
    if lines.is_empty() {
        vec![String::new()]
    } else {
        lines
    }
}
