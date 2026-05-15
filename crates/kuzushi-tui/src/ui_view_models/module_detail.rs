use crate::ShellApp;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModulePromptOnDisk {
    pub(crate) verb: String,
    pub(crate) path: String,
}

pub(crate) fn module_prompts_model(app: &ShellApp, module_id: &str) -> Vec<ModulePromptOnDisk> {
    let root = prompt_root(app, module_id);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut prompts: Vec<ModulePromptOnDisk> = entries
        .flatten()
        .filter_map(|entry| prompt_from_entry(app, entry))
        .collect();
    prompts.sort_by(|a, b| a.verb.cmp(&b.verb));
    prompts
}

fn prompt_root(app: &ShellApp, module_id: &str) -> PathBuf {
    app.target
        .as_deref()
        .map(|target| target.join(".kuzushi/prompts").join(module_id))
        .unwrap_or_else(|| PathBuf::from(".kuzushi/prompts").join(module_id))
}

fn prompt_from_entry(app: &ShellApp, entry: std::fs::DirEntry) -> Option<ModulePromptOnDisk> {
    if !entry.metadata().ok()?.is_file() {
        return None;
    }
    let name = entry.file_name().to_string_lossy().to_string();
    if !name.ends_with(".md") {
        return None;
    }
    Some(ModulePromptOnDisk {
        verb: name.trim_end_matches(".md").to_string(),
        path: display_prompt_path(app, &entry.path()),
    })
}

fn display_prompt_path(app: &ShellApp, path: &Path) -> String {
    path.strip_prefix(workspace_root(app))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn workspace_root(app: &ShellApp) -> &Path {
    app.target.as_deref().unwrap_or_else(|| Path::new("."))
}
