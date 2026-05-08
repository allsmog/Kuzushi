use super::prelude::*;
use super::*;

pub(in crate::modules) fn list_shinsa_frameworks(input: Value) -> Result<Value> {
    let spec = PluginAdapterSpec {
        tool_name: "shinsa:frameworks",
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "skills": [],
                    "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
                },
            }));
        }
    };
    let skills_root = root.join("skills");
    let mut skills = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&skills_root) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                skills.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    skills.sort();
    Ok(json!({
        "ok": true,
        "output": format!("shinsa-plugin path: {}\nSkill modules: {}", root.display(), skills.len()),
        "data": {
            "pluginRoot": root.display().to_string(),
            "skills": skills,
            "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
        },
    }))
}
