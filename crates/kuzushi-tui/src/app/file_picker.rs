use super::*;
use crate::app::state_transitions::InputUpdate;
use std::path::{Path, PathBuf};

mod discovery;
mod review_evidence;
#[cfg(test)]
use discovery::{
    synthetic_file_candidates, FileDiscovery, FileDiscoveryBudget, FILE_PICKER_DIRECTORY_CHUNK,
};
pub(crate) use discovery::{workspace_file_candidates, workspace_file_candidates_cancellable};
pub(crate) use review_evidence::ReviewFileSelection;

pub(crate) const FILE_PICKER_MAX_FILES: usize = 5_000;
const FILE_PICKER_PAGE_STEP: usize = 10;

impl ShellApp {
    pub(crate) fn open_file_picker(&mut self) {
        self.open_file_picker_for(FilePickerPurpose::KnowledgeBase);
    }

    pub(crate) fn open_map_document_picker(&mut self) {
        let Some(_) = self.router.setup().map_run_config().text() else {
            return;
        };
        self.open_file_picker_for(FilePickerPurpose::MapDocument);
    }

    fn open_file_picker_for(&mut self, purpose: FilePickerPurpose) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let index = self.workspace_file_completion_index();
        let truncation_hint = index.truncation_hint();
        let truncated = index.is_truncated();
        let origin = self.shell_view();
        self.router.navigation_mut().push_overlay_origin(origin);
        self.router.file_picker_mut().open(index.values, truncated);
        self.router.file_picker_mut().set_purpose(purpose);
        self.set_shell_view(ShellView::FilePicker);
        self.log_file_picker_open(workspace.root(), truncation_hint);
    }

    fn log_file_picker_open(&mut self, root: &Path, truncation_hint: Option<&str>) {
        let route = self.router.file_picker();
        let suffix = truncation_hint
            .map(|hint| format!(" ({hint})"))
            .unwrap_or_default();
        self.log(
            "files",
            format!(
                "{} file(s) under {}{suffix}",
                route.files().len(),
                root.display()
            ),
        );
    }

    pub(crate) fn handle_file_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        if self.handle_review_file_picker_key(key) {
            return InputUpdate::handled();
        }
        match key.code {
            KeyCode::Up => self.router.file_picker_mut().move_cursor(-1),
            KeyCode::Down => self.router.file_picker_mut().move_cursor(1),
            KeyCode::PageUp => self
                .router
                .file_picker_mut()
                .move_cursor(-(FILE_PICKER_PAGE_STEP as isize)),
            KeyCode::PageDown => self
                .router
                .file_picker_mut()
                .move_cursor(FILE_PICKER_PAGE_STEP as isize),
            KeyCode::Enter => return self.accept_file_picker_selection(),
            KeyCode::Esc => self.close_file_picker(),
            _ => self.router.file_picker_mut().edit_query(key),
        }
        InputUpdate::handled()
    }

    pub(crate) fn filtered_file_picker_paths(&self) -> Vec<String> {
        self.router.file_picker().filtered_paths()
    }

    pub(crate) fn workspace_file_completion_index(&self) -> FileCompletionIndex {
        self.workbench_cache()
            .borrow()
            .cached_file_completion_index(self.target())
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn refresh_open_file_picker_candidates(&mut self) {
        if self.shell_view() != ShellView::FilePicker {
            return;
        }
        let index = self.workspace_file_completion_index();
        let truncated = index.is_truncated();
        self.router
            .file_picker_mut()
            .replace_files(index.values, truncated);
    }

    pub(crate) fn attachment_effects_from_paste(&mut self, text: &str) -> Option<Vec<ShellEffect>> {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(_) => return None,
        };
        pasted_workspace_files(text, workspace.root()).map(attachment_effects)
    }

    fn accept_file_picker_selection(&mut self) -> InputUpdate {
        if self.router.file_picker().purpose() == FilePickerPurpose::ReviewEvidence {
            self.apply_review_source_files();
            return InputUpdate::handled();
        }
        let Some(source) = self.router.file_picker().selected_path() else {
            self.log("files", "no file matches the current filter");
            return InputUpdate::handled();
        };
        if self.router.file_picker().purpose() == FilePickerPurpose::MapDocument {
            return self.accept_map_document_selection(source);
        }
        InputUpdate::handled_with_effects(vec![attachment_effect(source)])
    }

    fn accept_map_document_selection(&mut self, source: String) -> InputUpdate {
        self.go_back();
        if let Some(list) = self.router.setup_mut().map_run_config_mut().text_mut() {
            if list.field.is_none() {
                list.add();
            }
            list.field = Some(FieldEditor::new(source));
        }
        let result = self.commit_map_text_edit();
        if let Err(error) = result {
            self.router
                .setup_mut()
                .map_run_config_mut()
                .set_error(error.to_string());
        }
        InputUpdate::handled()
    }

    fn close_file_picker(&mut self) {
        self.go_back();
        self.log("files", "closed file picker");
    }
}

fn attachment_effects(files: Vec<String>) -> Vec<ShellEffect> {
    files.into_iter().map(attachment_effect).collect()
}

fn attachment_effect(source: String) -> ShellEffect {
    ShellEffect::AttachKnowledgeBaseSource(KnowledgeBaseAttach { source })
}

pub(crate) fn file_completion_values_for(app: &ShellApp) -> CompletionValues<'_> {
    let target = app.target();
    CompletionValues::Borrowed(std::cell::Ref::map(
        app.workbench_cache().borrow(),
        |cache| cache.cached_file_completion_values(target),
    ))
}

fn pasted_workspace_files(text: &str, root: &Path) -> Option<Vec<String>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw_paths = if workspace_relative_file(root, trimmed).is_some() {
        vec![trimmed.to_string()]
    } else {
        shell_like_words(trimmed)
    };
    let files = raw_paths
        .iter()
        .map(|raw| workspace_relative_file(root, raw))
        .collect::<Option<Vec<_>>>()?;
    (!files.is_empty()).then_some(files)
}

fn workspace_relative_file(root: &Path, raw: &str) -> Option<String> {
    let raw = raw.strip_prefix("file://").unwrap_or(raw);
    let path = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        root.join(raw)
    };
    let metadata = path.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let path = path.canonicalize().ok()?;
    path.strip_prefix(root)
        .ok()
        .map(|relative| relative.to_string_lossy().into_owned())
}

fn shell_like_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in input.chars() {
        let action = shell_word_action(ch, quote, escaped);
        escaped = matches!(action, ShellWordAction::Escape);
        match action {
            ShellWordAction::Literal(ch) => current.push(ch),
            ShellWordAction::Escape => {}
            ShellWordAction::OpenQuote(ch) => quote = Some(ch),
            ShellWordAction::CloseQuote => quote = None,
            ShellWordAction::Separator => push_word(&mut words, &mut current),
        }
    }
    if escaped {
        current.push('\\');
    }
    push_word(&mut words, &mut current);
    words
}

#[derive(Clone, Copy)]
enum ShellWordAction {
    Literal(char),
    Escape,
    OpenQuote(char),
    CloseQuote,
    Separator,
}

fn shell_word_action(ch: char, quote: Option<char>, escaped: bool) -> ShellWordAction {
    if escaped {
        return ShellWordAction::Literal(ch);
    }
    if ch == '\\' {
        return ShellWordAction::Escape;
    }
    quote_action(ch, quote).unwrap_or_else(|| unquoted_shell_word_action(ch, quote))
}

fn quote_action(ch: char, quote: Option<char>) -> Option<ShellWordAction> {
    match (ch, quote) {
        ('\'' | '"', Some(open)) if open == ch => Some(ShellWordAction::CloseQuote),
        ('\'' | '"', None) => Some(ShellWordAction::OpenQuote(ch)),
        _ => None,
    }
}

fn unquoted_shell_word_action(ch: char, quote: Option<char>) -> ShellWordAction {
    if ch.is_whitespace() && quote.is_none() {
        ShellWordAction::Separator
    } else {
        ShellWordAction::Literal(ch)
    }
}

fn push_word(words: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        words.push(std::mem::take(current));
    }
}

#[cfg(test)]
mod tests;
