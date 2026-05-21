use crate::capabilities::prompt_armor::domain::output_dir;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn config(target: &Path, action: &str) -> Result<Value> {
    let path = target.join("promptarmor.yaml");
    scaffold_config_if_requested(&path, action)?;
    Ok(config_response(&path, action))
}

fn scaffold_config_if_requested(path: &Path, action: &str) -> Result<()> {
    should_scaffold_config(path, action)
        .then(|| write_default_config(path))
        .transpose()
        .map(|_| ())
}

fn should_scaffold_config(path: &Path, action: &str) -> bool {
    action == "init" && !path.exists()
}

fn write_default_config(path: &Path) -> Result<()> {
    fs::write(
        path,
        "version: 1\nsuites:\n  - injection\n  - tool-abuse\nmutations: []\n",
    )
    .with_context(|| format!("Could not write {}", path.display()))
}

fn config_response(path: &Path, action: &str) -> Value {
    let exists = path.exists();
    let output = config_output(path, action, exists);
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "path": path.display().to_string(),
            "exists": exists,
            "content": config_body(path, exists),
        }),
    )
}

fn config_body(path: &Path, exists: bool) -> String {
    exists
        .then(|| fs::read_to_string(path).unwrap_or_default())
        .unwrap_or_default()
}

fn config_output(path: &Path, action: &str, exists: bool) -> String {
    if exists {
        format!("prompt-armor:config {action}\nConfig: {}", path.display())
    } else {
        format!("prompt-armor:config found no promptarmor.yaml at {}. Run with {{\"action\":\"init\"}} to scaffold one.", path.display())
    }
}

pub(crate) fn diff(path_a: PathBuf, path_b: PathBuf) -> Result<Value> {
    let text_a = fs::read_to_string(&path_a).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_a.display()
        )
    })?;
    let text_b = fs::read_to_string(&path_b).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_b.display()
        )
    })?;
    let delta = text_b.lines().count() as isize - text_a.lines().count() as isize;
    let output = format!(
        "prompt-armor:diff complete\n  runA: {}\n  runB: {}\n  lineDelta: {}",
        path_a.display(),
        path_b.display(),
        delta
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "runA": path_a.display().to_string(),
            "runB": path_b.display().to_string(),
            "lineDelta": delta,
        }),
    ))
}

pub(crate) fn report(target: &Path, output: PathBuf) -> Result<Value> {
    let out_dir = output_dir(target);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Could not create {}", out_dir.display()))?;
    let entries = sorted_artifact_entries(&out_dir);
    let body = report_markdown(&entries);
    fs::write(&output, &body).with_context(|| format!("Could not write {}", output.display()))?;
    let message = format!("prompt-armor:report complete\nReport: {}", output.display());
    let mut result = crate::module_result::completed_output_result(
        message.clone(),
        message,
        json!({
            "reportPath": output.display().to_string(),
            "artifacts": entries,
        }),
    );
    result["artifacts"] = json!([{ "label": "report", "path": output.display().to_string() }]);
    Ok(result)
}

fn sorted_artifact_entries(out_dir: &Path) -> Vec<String> {
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&out_dir) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    entries
}

fn report_markdown(entries: &[String]) -> String {
    format!(
        "# PromptArmor Report\n\nArtifacts in `.prompt-armor`: {}\n",
        if entries.is_empty() {
            "none".to_string()
        } else {
            entries.join(", ")
        }
    )
}
