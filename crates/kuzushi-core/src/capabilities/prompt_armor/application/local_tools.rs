use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_PROMPT_ARMOR_TEXT_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn config(target: &Path, action: &str) -> Result<Value> {
    let path = target.join("promptarmor.yaml");
    scaffold_config_if_requested(target, &path, action)?;
    config_response(target, &path, action)
}

fn scaffold_config_if_requested(target: &Path, path: &Path, action: &str) -> Result<()> {
    should_scaffold_config(path, action)
        .then(|| write_default_config(target))
        .transpose()
        .map(|_| ())
}

fn should_scaffold_config(path: &Path, action: &str) -> bool {
    action == "init"
        && fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn write_default_config(target: &Path) -> Result<PathBuf> {
    crate::workspace::write_workspace_file(
        target,
        "promptarmor.yaml",
        b"version: 1\nsuites:\n  - injection\n  - tool-abuse\nmutations: []\n",
    )
    .with_context(|| {
        format!(
            "Could not write {}",
            target.join("promptarmor.yaml").display()
        )
    })
}

fn config_response(target: &Path, path: &Path, action: &str) -> Result<Value> {
    let exists = config_exists(path)?;
    let output = config_output(path, action, exists);
    let content = if exists {
        crate::bounded_file::read_utf8_text_within(target, path, MAX_PROMPT_ARMOR_TEXT_BYTES)
            .with_context(|| format!("Could not read {}", path.display()))?
    } else {
        String::new()
    };
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "path": path.display().to_string(),
            "exists": exists,
            "content": content,
        }),
    ))
}

fn config_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn config_output(path: &Path, action: &str, exists: bool) -> String {
    if exists {
        format!("prompt-armor:config {action}\nConfig: {}", path.display())
    } else {
        format!("prompt-armor:config found no promptarmor.yaml at {}. Run with {{\"action\":\"init\"}} to scaffold one.", path.display())
    }
}

pub(crate) fn diff(target: &Path, path_a: PathBuf, path_b: PathBuf) -> Result<Value> {
    let text_a =
        crate::bounded_file::read_utf8_text_within(target, &path_a, MAX_PROMPT_ARMOR_TEXT_BYTES)
            .with_context(|| {
                format!(
                    "Could not read prompt-armor diff input {}",
                    path_a.display()
                )
            })?;
    let text_b =
        crate::bounded_file::read_utf8_text_within(target, &path_b, MAX_PROMPT_ARMOR_TEXT_BYTES)
            .with_context(|| {
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
    let out_dir = crate::workspace::ensure_workspace_output_dir(target, ".prompt-armor")?;
    let entries = sorted_artifact_entries(&out_dir)?;
    let body = report_markdown(&entries);
    let relative = output.strip_prefix(target).with_context(|| {
        format!(
            "PromptArmor report {} must stay inside target {}",
            output.display(),
            target.display()
        )
    })?;
    let output = crate::workspace::write_workspace_file(target, relative, body.as_bytes())?;
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

fn sorted_artifact_entries(out_dir: &Path) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(out_dir)
        .with_context(|| format!("Could not read {}", out_dir.display()))?
        .take(10_000)
    {
        let entry = entry.with_context(|| format!("Could not inspect {}", out_dir.display()))?;
        entries.push(
            entry
                .file_name()
                .to_string_lossy()
                .chars()
                .take(512)
                .collect(),
        );
    }
    entries.sort();
    Ok(entries)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn config_does_not_read_or_overwrite_outside_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside.yaml");
        fs::create_dir_all(&target).unwrap();
        fs::write(&outside, "OUTSIDE-PROMPT-ARMOR-SECRET").unwrap();
        std::os::unix::fs::symlink(&outside, target.join("promptarmor.yaml")).unwrap();

        for action in ["show", "init"] {
            let error = config(&target, action).unwrap_err();
            assert!(!format!("{error:#}").contains("OUTSIDE-PROMPT-ARMOR-SECRET"));
        }
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "OUTSIDE-PROMPT-ARMOR-SECRET"
        );
        assert!(!crate::workspace::workspace_objects_dir(&target).exists());
    }

    #[cfg(unix)]
    #[test]
    fn report_does_not_follow_preplanted_output_symlinks() {
        use std::os::unix::fs::symlink;

        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::create_dir(target.path().join(".prompt-armor")).unwrap();
        fs::write(outside.path(), "outside sentinel").unwrap();
        symlink(outside.path(), target.path().join("report.md")).unwrap();

        assert!(report(target.path(), target.path().join("report.md")).is_err());
        assert_eq!(
            fs::read_to_string(outside.path()).unwrap(),
            "outside sentinel"
        );
    }
}
