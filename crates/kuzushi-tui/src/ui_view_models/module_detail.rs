use crate::ShellApp;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleDetailModel {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) summary: String,
    pub(crate) primary_tool: String,
    pub(crate) tools_section: ModuleToolsSection,
    pub(crate) options_section: Option<ModuleKeyValueSection>,
    pub(crate) prompts_section: Option<ModuleKeyValueSection>,
    pub(crate) stats_section: Option<ModuleKeyValueSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleToolsSection {
    pub(crate) header: &'static str,
    pub(crate) rows: Vec<ModuleToolRow>,
    pub(crate) empty_message: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleKeyValueSection {
    pub(crate) header: String,
    pub(crate) rows: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModulePromptOnDisk {
    pub(crate) verb: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModuleToolRow {
    pub(crate) cells: [String; 3],
}

pub(crate) fn focused_module_detail_model(app: &ShellApp) -> Option<ModuleDetailModel> {
    let module_id = app.focused_module.as_deref()?;
    module_detail_model(app, module_id)
}

pub(crate) fn module_detail_model(app: &ShellApp, module_id: &str) -> Option<ModuleDetailModel> {
    let module = app
        .registry
        .modules()
        .find(|module| module.metadata().id == module_id)?;
    let visible_tools = visible_module_tools(module);
    let primary_tool = visible_tools
        .first()
        .map(|tool| tool.cells[0].clone())
        .unwrap_or_else(|| "no-tool".to_string());
    let stored_options = module_stored_options(app, &visible_tools);
    let prompts = module_prompts_model(app, module_id);
    let log_count = module_log_count(app, module_id);
    Some(ModuleDetailModel {
        id: module.metadata().id.clone(),
        name: module.metadata().name.clone(),
        summary: module.metadata().description.clone(),
        primary_tool,
        tools_section: module_tools_section(&visible_tools),
        options_section: module_options_section(&stored_options),
        prompts_section: module_prompts_section(&prompts),
        stats_section: module_stats_section(module_id, log_count, visible_tools.len()),
    })
}

pub(crate) fn module_prompts_model(app: &ShellApp, module_id: &str) -> Vec<ModulePromptOnDisk> {
    let root = prompt_root(app, module_id);
    if !root.exists() {
        return Vec::new();
    };
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(_) => return vec![malformed_prompt_root(app, &root)],
    };
    let mut prompts: Vec<ModulePromptOnDisk> = entries
        .flatten()
        .filter_map(|entry| prompt_from_entry(app, entry))
        .collect();
    prompts.sort_by(|a, b| a.verb.cmp(&b.verb));
    prompts
}

fn malformed_prompt_root(app: &ShellApp, root: &Path) -> ModulePromptOnDisk {
    ModulePromptOnDisk {
        verb: "artifact-load".to_string(),
        path: format!("{} (unreadable)", display_prompt_path(app, root)),
    }
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

fn visible_module_tools(module: &kuzushi_core::BuiltinModule) -> Vec<ModuleToolRow> {
    module
        .tools()
        .iter()
        .filter(|tool| !tool.hidden)
        .map(|tool| ModuleToolRow {
            cells: [
                tool.name.clone(),
                tool_status_label(tool.headless).to_string(),
                tool.description.clone(),
            ],
        })
        .collect()
}

fn tool_status_label(headless: bool) -> &'static str {
    if headless {
        "headless"
    } else {
        "interactive"
    }
}

fn module_tools_section(tools: &[ModuleToolRow]) -> ModuleToolsSection {
    ModuleToolsSection {
        header: "TOOLS",
        rows: tools.to_vec(),
        empty_message: tools
            .is_empty()
            .then_some("No shell tools are exposed by this module."),
    }
}

fn module_options_section(options: &[(String, String)]) -> Option<ModuleKeyValueSection> {
    (!options.is_empty()).then(|| ModuleKeyValueSection {
        header: format!("OPTIONS · {}", options.len()),
        rows: options.to_vec(),
    })
}

fn module_prompts_section(prompts: &[ModulePromptOnDisk]) -> Option<ModuleKeyValueSection> {
    (!prompts.is_empty()).then(|| ModuleKeyValueSection {
        header: format!("PROMPTS · {}", prompts.len()),
        rows: prompts
            .iter()
            .map(|prompt| (prompt.verb.clone(), prompt.path.clone()))
            .collect(),
    })
}

fn module_stats_section(
    module_id: &str,
    log_count: usize,
    tool_count: usize,
) -> Option<ModuleKeyValueSection> {
    (log_count > 0).then(|| ModuleKeyValueSection {
        header: "STATS · this session".to_string(),
        rows: vec![
            (
                "log entries".to_string(),
                format!("{log_count} from `{module_id}`"),
            ),
            ("tools bound".to_string(), tool_count.to_string()),
        ],
    })
}

fn module_stored_options(app: &ShellApp, tools: &[ModuleToolRow]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tool in tools {
        let tool_name = &tool.cells[0];
        let stored = app.option_store.effective_stored_values(tool_name);
        for (name, value) in stored.iter() {
            out.push((format!("{tool_name}::{name}"), format_json_value(value)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn module_log_count(app: &ShellApp, module_id: &str) -> usize {
    app.log
        .iter()
        .filter(|line| is_module_log_line(line, module_id))
        .count()
}

fn is_module_log_line(line: &crate::app::LogLine, module_id: &str) -> bool {
    line.prefix == module_id || line.prefix.starts_with(&format!("{module_id}:"))
}

fn format_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{ToolOptionStore, V2Config};

    #[test]
    fn focused_module_detail_model_uses_current_focus() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.focused_module = Some("sast".to_string());

        let model = focused_module_detail_model(&app).expect("focused module detail");

        assert_eq!(model.id, "sast");
        assert!(!model.tools_section.rows.is_empty());
        assert_eq!(model.tools_section.header, "TOOLS");
        assert!(model.tools_section.empty_message.is_none());
        assert!(model
            .tools_section
            .rows
            .iter()
            .all(|tool| tool.cells[1] == "headless" || tool.cells[1] == "interactive"));
    }

    #[test]
    fn focused_module_detail_model_is_empty_without_focus() {
        let app = ShellApp::new(V2Config::default(), None);

        assert!(focused_module_detail_model(&app).is_none());
    }

    #[test]
    fn module_detail_model_shapes_options_section() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store = ToolOptionStore::new();
        app.focused_module = Some("sast".to_string());
        app.option_store.set_value(
            kuzushi_core::OptionScope::Session,
            kuzushi_core::OptionTarget::Tool("sast:scan".to_string()),
            "triage",
            serde_json::json!(true),
        );

        let model = focused_module_detail_model(&app).expect("focused module detail");
        let options = model.options_section.expect("options section");

        assert_eq!(options.header, "OPTIONS · 1");
        assert_eq!(
            options.rows,
            vec![("sast:scan::triage".to_string(), "true".to_string())]
        );
    }

    #[test]
    fn module_detail_model_shapes_prompt_section() {
        let temp = tempfile::tempdir().unwrap();
        let prompt_root = temp.path().join(".kuzushi/prompts/sast");
        std::fs::create_dir_all(&prompt_root).unwrap();
        std::fs::write(prompt_root.join("triage.md"), "triage").unwrap();
        std::fs::write(prompt_root.join("system.md"), "system").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());
        app.focused_module = Some("sast".to_string());

        let model = focused_module_detail_model(&app).expect("focused module detail");
        let prompts = model.prompts_section.expect("prompts section");

        assert_eq!(prompts.header, "PROMPTS · 2");
        assert_eq!(prompts.rows[0].0, "system");
        assert_eq!(prompts.rows[1].0, "triage");
    }

    #[test]
    fn module_detail_model_surfaces_unreadable_prompt_root() {
        let temp = tempfile::tempdir().unwrap();
        let prompt_root = temp.path().join(".kuzushi/prompts/sast");
        std::fs::create_dir_all(prompt_root.parent().unwrap()).unwrap();
        std::fs::write(&prompt_root, "not a directory").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());
        app.focused_module = Some("sast".to_string());

        let model = focused_module_detail_model(&app).expect("focused module detail");
        let prompts = model.prompts_section.expect("prompts section");

        assert_eq!(prompts.header, "PROMPTS · 1");
        assert_eq!(prompts.rows[0].0, "artifact-load");
        assert_eq!(
            prompts.rows[0].1,
            ".kuzushi/prompts/sast (unreadable)".to_string()
        );
    }
}
