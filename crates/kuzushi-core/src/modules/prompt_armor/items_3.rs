use super::prelude::*;
use super::*;

pub(in crate::modules) fn build_prompt(
    command: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("Run PromptArmor /{command} using the provided inputs."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "For scan and attack, the caller has supplied the required authorization gate.".to_string(),
    ];
    for key in [
        "endpoint",
        "suites",
        "mutations",
        "config",
        "paths",
        "focus",
        "attack",
        "mutation",
        "payload",
    ] {
        if let Some(value) = input.get(key) {
            lines.push(format!("{key}: {}", json_summary(value)));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

pub(in crate::modules) fn config(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let path = target.join("promptarmor.yaml");
    let action = string_input_any(&input, &["action"]).unwrap_or_else(|| "show".to_string());
    if action == "init" && !path.exists() {
        fs::write(
            &path,
            "version: 1\nsuites:\n  - injection\n  - tool-abuse\nmutations: []\n",
        )
        .with_context(|| format!("Could not write {}", path.display()))?;
    }
    let exists = path.exists();
    let body = if exists {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(json!({
        "ok": true,
        "output": if exists {
            format!("prompt-armor:config {action}\nConfig: {}", path.display())
        } else {
            format!("prompt-armor:config found no promptarmor.yaml at {}. Run with {{\"action\":\"init\"}} to scaffold one.", path.display())
        },
        "data": {
            "path": path.display().to_string(),
            "exists": exists,
            "content": body,
        },
    }))
}

pub(in crate::modules) fn diff(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let run_a =
        string_input_any(&input, &["runA", "run_a"]).context("prompt-armor:diff requires runA")?;
    let run_b =
        string_input_any(&input, &["runB", "run_b"]).context("prompt-armor:diff requires runB")?;
    let path_a = resolve_input_path(&target, &run_a);
    let path_b = resolve_input_path(&target, &run_b);
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
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:diff complete\n  runA: {}\n  runB: {}\n  lineDelta: {}", path_a.display(), path_b.display(), delta),
        "data": {
            "runA": path_a.display().to_string(),
            "runB": path_b.display().to_string(),
            "lineDelta": delta,
        },
    }))
}
