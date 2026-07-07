use super::*;
use crate::app::state_transitions::InputUpdate;
use std::fs;
use std::path::{Path, PathBuf};

const FILE_PICKER_MAX_FILES: usize = 5_000;
const FILE_PICKER_PAGE_STEP: usize = 10;

impl ShellApp {
    pub(crate) fn open_file_picker(&mut self) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let (files, truncated) = workspace_file_candidates(workspace.root(), FILE_PICKER_MAX_FILES);
        let origin = self.shell_view();
        self.router
            .navigation_mut()
            .push_overlay_origin(origin);
        self.router.file_picker_mut().open(files, truncated);
        self.set_shell_view(ShellView::FilePicker);
        self.log_file_picker_open(workspace.root());
    }

    fn log_file_picker_open(&mut self, root: &Path) {
        let route = self.router.file_picker();
        let suffix = if route.truncated() {
            format!(" (capped at {FILE_PICKER_MAX_FILES})")
        } else {
            String::new()
        };
        self.log(
            "files",
            format!(
                "{} attachable file(s) under {}{suffix}",
                route.files().len(),
                root.display()
            ),
        );
    }

    pub(crate) fn handle_file_picker_key(&mut self, key: KeyEvent) -> InputUpdate {
        let query_empty = self.router.file_picker().query().is_empty();
        match key.code {
            KeyCode::Up => self.router.file_picker_mut().move_cursor(-1),
            KeyCode::Down => self.router.file_picker_mut().move_cursor(1),
            KeyCode::Char('k') if query_empty => self.router.file_picker_mut().move_cursor(-1),
            KeyCode::Char('j') if query_empty => self.router.file_picker_mut().move_cursor(1),
            KeyCode::PageUp => self
                .router
                .file_picker_mut()
                .move_cursor(-(FILE_PICKER_PAGE_STEP as isize)),
            KeyCode::PageDown => self
                .router
                .file_picker_mut()
                .move_cursor(FILE_PICKER_PAGE_STEP as isize),
            KeyCode::Backspace => self.router.file_picker_mut().pop_query(),
            KeyCode::Delete => self.router.file_picker_mut().clear_query(),
            KeyCode::Enter => return self.accept_file_picker_selection(),
            KeyCode::Esc => self.close_file_picker(),
            KeyCode::Char('q') if query_empty => self.close_file_picker(),
            KeyCode::Char(ch) if !ch.is_control() => self.router.file_picker_mut().push_query(ch),
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    pub(crate) fn filtered_file_picker_paths(&self) -> Vec<String> {
        self.router.file_picker().filtered_paths()
    }

    pub(crate) fn workspace_file_completion_values(&self) -> Vec<String> {
        let Some(root) = self.target() else {
            return Vec::new();
        };
        workspace_file_candidates(root, FILE_PICKER_MAX_FILES).0
    }

    pub(crate) fn attachment_effects_from_paste(&mut self, text: &str) -> Option<Vec<ShellEffect>> {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(_) => return None,
        };
        pasted_workspace_files(text, workspace.root()).map(attachment_effects)
    }

    fn accept_file_picker_selection(&mut self) -> InputUpdate {
        let Some(source) = self.router.file_picker().selected_path() else {
            self.log("files", "no file matches the current filter");
            return InputUpdate::handled();
        };
        InputUpdate::handled_with_effects(vec![attachment_effect(source)])
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

pub(crate) fn file_completion_values_for(app: &ShellApp) -> Vec<String> {
    app.workspace_file_completion_values()
}

fn workspace_file_candidates(root: &Path, limit: usize) -> (Vec<String>, bool) {
    let mut files = Vec::new();
    let truncated = collect_workspace_files(root, root, limit, &mut files);
    files.sort();
    (files, truncated)
}

fn collect_workspace_files(
    root: &Path,
    current: &Path,
    limit: usize,
    out: &mut Vec<String>,
) -> bool {
    if out.len() >= limit {
        return true;
    }
    let Ok(entries) = fs::read_dir(current) else {
        return false;
    };
    for entry in sorted_dir_entries(entries) {
        if collect_workspace_entry(root, entry, limit, out) {
            return true;
        }
    }
    false
}

fn sorted_dir_entries(entries: fs::ReadDir) -> Vec<fs::DirEntry> {
    let mut entries = entries.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().into_owned());
    entries
}

fn collect_workspace_entry(
    root: &Path,
    entry: fs::DirEntry,
    limit: usize,
    out: &mut Vec<String>,
) -> bool {
    let path = entry.path();
    let Ok(file_type) = entry.file_type() else {
        return false;
    };
    if file_type.is_dir() {
        return !ignored_picker_dir(&path) && collect_workspace_files(root, &path, limit, out);
    }
    if file_type.is_file() {
        push_relative_file(root, &path, out);
    }
    out.len() >= limit
}

fn push_relative_file(root: &Path, path: &Path, out: &mut Vec<String>) {
    if let Ok(relative) = path.strip_prefix(root) {
        out.push(relative.to_string_lossy().into_owned());
    }
}

fn ignored_picker_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    matches!(
        name,
        ".git" | ".kuzushi" | "node_modules" | "target" | "dist" | "build" | ".next" | "coverage"
    )
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
