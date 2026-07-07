use super::*;

pub(in crate::modules) fn with_sast_prompt_override(
    subtool_input: Value,
    scan_input: &Value,
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    option_key: &str,
) -> Result<Value> {
    let Value::Object(mut object) = subtool_input else {
        return Ok(subtool_input);
    };
    if object.contains_key(option_key) {
        return Ok(Value::Object(object));
    }
    if let Some(value) = scan_input.get(option_key).cloned() {
        object.insert(option_key.to_string(), value);
        return Ok(Value::Object(object));
    }
    if let Some(text) = read_sast_prompt_override(ctx, verb, option_key)? {
        object.insert(option_key.to_string(), Value::String(text));
    }
    Ok(Value::Object(object))
}

fn read_sast_prompt_override(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    option_key: &str,
) -> Result<Option<String>> {
    let Some(workspace) = ctx.workspace else {
        return Ok(None);
    };
    let path = crate::options::prompt_override_path(workspace.root(), "sast", verb);
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => Ok(Some(text)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("Could not read {option_key} from {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{V2Config, WorkspaceTarget};

    fn context<'a>(
        config: &'a V2Config,
        workspace: &'a WorkspaceTarget,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        }
    }

    #[test]
    fn with_sast_prompt_override_reads_project_prompt_file() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path = crate::options::prompt_override_path(temp.path(), "sast", "triage");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "focus authz\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let input = with_sast_prompt_override(
            json!({"scanId": "scan-1"}),
            &json!({}),
            &ctx,
            "triage",
            "TRIAGE_PROMPT",
        )
        .unwrap();

        assert_eq!(input["TRIAGE_PROMPT"], json!("focus authz\n"));
    }

    #[test]
    fn with_sast_prompt_override_prefers_scan_input() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let path = crate::options::prompt_override_path(temp.path(), "sast", "triage");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "file prompt\n").unwrap();
        let config = V2Config::default();
        let ctx = context(&config, &workspace);

        let input = with_sast_prompt_override(
            json!({"scanId": "scan-1"}),
            &json!({"TRIAGE_PROMPT": "explicit prompt"}),
            &ctx,
            "triage",
            "TRIAGE_PROMPT",
        )
        .unwrap();

        assert_eq!(input["TRIAGE_PROMPT"], json!("explicit prompt"));
    }
}
