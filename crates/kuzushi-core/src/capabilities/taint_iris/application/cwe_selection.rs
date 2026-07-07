use super::*;

pub(crate) fn run_taint_cwe_select_value(
    input: &Value,
    target: &Path,
    runtime: Option<&dyn AgentRuntime>,
    model: Option<&str>,
) -> Result<Vec<TaintCweSelection>> {
    if let Some(cwes) = parse_taint_cwes_from_input(input)? {
        return Ok(cwes);
    }

    let runtime = runtime.context(
        "pipeline:taint-cwe-select requires the LangGraph runtime unless cwes are supplied explicitly",
    )?;
    let model = crate::runtime::resolve_explicit_model(
        "pipeline:taint-cwe-select",
        model.map(str::to_string),
        None,
    )?;
    let inventory = collect_agentic_repo_inventory(target, 60, 1024)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.to_path_buf(),
            TAINT_CWE_SELECT_SYSTEM_PROMPT.to_string(),
            build_taint_cwe_select_prompt(target, &inventory),
        )
        .with_tool_policy(agent_tool_policy_for_input_and_target(input, target)?),
        StructuredJsonContract::new(
            "pipeline:taint-cwe-select",
            "TaintCweSelection",
            taint_cwe_selection_schema(),
        ),
        require_json_object,
    )?;
    parse_taint_cwe_select_raw(raw)
}

pub(crate) fn parse_taint_cwes_from_input(input: &Value) -> Result<Option<Vec<TaintCweSelection>>> {
    if let Some(value) = input.get("cwe").or_else(|| input.get("cwes")) {
        return parse_taint_cwes_value(value).map(Some);
    }
    Ok(None)
}

pub(crate) fn parse_taint_cwes_value(value: &Value) -> Result<Vec<TaintCweSelection>> {
    match value {
        Value::String(text) => Ok(text
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|id| TaintCweSelection {
                id: id.to_string(),
                name: id.to_string(),
                reason: "operator-supplied".to_string(),
            })
            .collect()),
        Value::Array(items) => {
            let mut cwes = Vec::new();
            for item in items {
                match item {
                    Value::String(id) => {
                        let id = id.trim();
                        if !id.is_empty() {
                            cwes.push(TaintCweSelection {
                                id: id.to_string(),
                                name: id.to_string(),
                                reason: "operator-supplied".to_string(),
                            });
                        }
                    }
                    Value::Object(object) => {
                        let id = read_object_string(object, &["id", "cwe"])
                            .context("taint-iris cwes entries require id or cwe")?;
                        let name =
                            read_object_string(object, &["name"]).unwrap_or_else(|| id.clone());
                        let reason = read_object_string(object, &["reason"])
                            .unwrap_or_else(|| "operator-supplied".to_string());
                        cwes.push(TaintCweSelection { id, name, reason });
                    }
                    _ => anyhow::bail!(
                        "taint-iris cwes must be a string, string array, or object array"
                    ),
                }
            }
            Ok(cwes)
        }
        _ => anyhow::bail!("taint-iris cwes must be a string or array"),
    }
}

pub(crate) fn parse_taint_cwe_select_raw(raw: Value) -> Result<Vec<TaintCweSelection>> {
    let Value::Object(object) = raw else {
        anyhow::bail!("pipeline:taint-cwe-select output parse failed: expected a JSON object");
    };
    let Some(value) = object.get("cwes") else {
        return Ok(Vec::new());
    };
    parse_taint_cwes_value(value)
}
