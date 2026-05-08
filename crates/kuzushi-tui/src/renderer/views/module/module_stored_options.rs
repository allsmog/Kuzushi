use super::*;

pub(crate) fn module_stored_options(
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tool in module.tools() {
        let stored = app.option_store.effective_stored_values(&tool.name);
        for (name, value) in stored.iter() {
            out.push((format!("{}::{}", tool.name, name), format_json_value(value)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[derive(Debug, Clone)]
pub(crate) struct ModulePromptOnDisk {
    pub(in crate::renderer::views) verb: String,
    pub(in crate::renderer::views) path: String,
}

pub(crate) fn module_prompts_on_disk(app: &ShellApp, module_id: &str) -> Vec<ModulePromptOnDisk> {
    let prompts_root = app
        .target
        .as_deref()
        .map(|t| t.join(".kuzushi/prompts").join(module_id))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/prompts").join(module_id));
    let Ok(entries) = std::fs::read_dir(&prompts_root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".md") {
            continue;
        }
        let verb = name.trim_end_matches(".md").to_string();
        out.push(ModulePromptOnDisk {
            verb,
            path: entry
                .path()
                .strip_prefix(app.target.as_deref().unwrap_or(std::path::Path::new(".")))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| entry.path().display().to_string()),
        });
    }
    out.sort_by(|a, b| a.verb.cmp(&b.verb));
    out
}

pub(crate) fn recent_module_log(
    app: &ShellApp,
    module_id: &str,
    take: usize,
) -> Vec<(String, String)> {
    let module_id = module_id.to_string();
    let mut matches: Vec<(String, String)> = app
        .log
        .iter()
        .rev()
        .filter(|line| {
            line.prefix == module_id
                || line.prefix.starts_with(&format!("{module_id}:"))
                || line.body.contains(&format!("{module_id}:"))
                || (module_id == "recon"
                    && (line.prefix == "tool" || line.prefix == "result")
                    && line.body.contains("recon"))
        })
        .take(take)
        .map(|line| (line.prefix.clone(), line.body.clone()))
        .collect();
    matches.reverse();
    matches
}
