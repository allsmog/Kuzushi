use super::*;

pub(crate) fn module_stored_options(
    app: &ShellApp,
    module: &kuzushi_core::BuiltinModule,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tool in visible_module_tools(module) {
        let stored = app.option_store.effective_stored_values(&tool.name);
        for (name, value) in stored.iter() {
            out.push((format!("{}::{}", tool.name, name), format_json_value(value)));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
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
