use super::*;
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
        self.file_picker_files = files;
        self.file_picker_query.clear();
        self.file_picker_cursor = 0;
        self.file_picker_truncated = truncated;
        if !matches!(self.shell_view, ShellView::FilePicker) {
            self.file_picker_return_view = Some(self.shell_view.clone());
        }
        self.shell_view = ShellView::FilePicker;
        self.log_file_picker_open(workspace.root());
    }

    fn log_file_picker_open(&mut self, root: &Path) {
        let suffix = if self.file_picker_truncated {
            format!(" (capped at {FILE_PICKER_MAX_FILES})")
        } else {
            String::new()
        };
        self.log(
            "files",
            format!(
                "{} attachable file(s) under {}{suffix}",
                self.file_picker_files.len(),
                root.display()
            ),
        );
    }

    pub(crate) fn handle_file_picker_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_file_picker_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_file_picker_cursor(1),
            KeyCode::PageUp => self.move_file_picker_cursor(-(FILE_PICKER_PAGE_STEP as isize)),
            KeyCode::PageDown => self.move_file_picker_cursor(FILE_PICKER_PAGE_STEP as isize),
            KeyCode::Backspace => self.pop_file_picker_query(),
            KeyCode::Delete => self.clear_file_picker_query(),
            KeyCode::Enter => self.accept_file_picker_selection(),
            KeyCode::Esc | KeyCode::Char('q') => self.close_file_picker(),
            KeyCode::Char(ch) if !ch.is_control() => self.push_file_picker_query(ch),
            _ => return false,
        }
        true
    }

    pub(crate) fn filtered_file_picker_paths(&self) -> Vec<String> {
        crate::app::line_editor::rank_fuzzy(
            crate::app::line_editor::dedupe_sorted(self.file_picker_files.clone()),
            &self.file_picker_query,
        )
    }

    pub(crate) fn workspace_file_completion_values(&self) -> Vec<String> {
        let Some(root) = self.target.as_deref() else {
            return Vec::new();
        };
        workspace_file_candidates(root, FILE_PICKER_MAX_FILES).0
    }

    pub(crate) fn attach_workspace_files_from_paste(&mut self, text: &str) -> bool {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(_) => return false,
        };
        let Some(files) = pasted_workspace_files(text, workspace.root()) else {
            return false;
        };
        for source in files {
            self.attach_kb_source(&source);
        }
        true
    }

    fn move_file_picker_cursor(&mut self, delta: isize) {
        let len = self.filtered_file_picker_paths().len();
        if len == 0 {
            self.file_picker_cursor = 0;
            return;
        }
        let current = (self.file_picker_cursor.min(len - 1)) as isize;
        self.file_picker_cursor = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn push_file_picker_query(&mut self, ch: char) {
        self.file_picker_query.push(ch);
        self.clamp_file_picker_cursor();
    }

    fn pop_file_picker_query(&mut self) {
        self.file_picker_query.pop();
        self.clamp_file_picker_cursor();
    }

    fn clear_file_picker_query(&mut self) {
        self.file_picker_query.clear();
        self.file_picker_cursor = 0;
    }

    fn clamp_file_picker_cursor(&mut self) {
        let len = self.filtered_file_picker_paths().len();
        self.file_picker_cursor = self.file_picker_cursor.min(len.saturating_sub(1));
    }

    fn accept_file_picker_selection(&mut self) {
        let matches = self.filtered_file_picker_paths();
        let Some(source) = matches.get(self.file_picker_cursor).cloned() else {
            self.log("files", "no file matches the current filter");
            return;
        };
        self.file_picker_return_view = None;
        self.attach_kb_source(&source);
    }

    fn close_file_picker(&mut self) {
        let return_view = self
            .file_picker_return_view
            .take()
            .unwrap_or(ShellView::KnowledgeBase);
        self.shell_view = return_view;
        self.log("files", "closed file picker");
    }
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
