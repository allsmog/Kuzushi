use super::*;

pub(crate) fn run_taint_cwe_select_value(
    input: &Value,
    target: &Path,
    runtime: Option<&dyn AgentRuntime>,
    model: Option<&str>,
) -> Result<CostedStructuredJson<Vec<TaintCweSelection>>> {
    if let Some(cwes) = parse_taint_cwes_from_input(input)? {
        return Ok(operator_cwe_selection(cwes));
    }

    query_taint_cwe_selection(input, target, runtime, model)
}

fn operator_cwe_selection(
    cwes: Vec<TaintCweSelection>,
) -> CostedStructuredJson<Vec<TaintCweSelection>> {
    CostedStructuredJson {
        value: cwes,
        cost_usd: 0.0,
        cost_usd_exact: true,
    }
}

fn query_taint_cwe_selection(
    input: &Value,
    target: &Path,
    runtime: Option<&dyn AgentRuntime>,
    model: Option<&str>,
) -> Result<CostedStructuredJson<Vec<TaintCweSelection>>> {
    let runtime = runtime.context(
        "pipeline:taint-cwe-select requires the LangGraph runtime unless cwes are supplied explicitly",
    )?;
    let model = crate::runtime::resolve_explicit_model(
        "pipeline:taint-cwe-select",
        model.map(str::to_string),
        None,
    )?;
    let inventory = collect_agentic_repo_inventory(target, 60, 1024)?;
    let request = AgentQueryRequest::new(
        model,
        target.to_path_buf(),
        TAINT_CWE_SELECT_SYSTEM_PROMPT.to_string(),
        build_taint_cwe_select_prompt(target, &inventory),
    )
    .with_tool_policy(agent_tool_policy_for_input_and_target(input, target)?);
    let raw = query_required_structured_json_with_cost(
        runtime,
        request,
        StructuredJsonContract::new(
            "pipeline:taint-cwe-select",
            "TaintCweSelection",
            taint_cwe_selection_schema(),
        ),
        require_json_object,
    )?;
    Ok(CostedStructuredJson {
        value: parse_taint_cwe_select_raw(raw.value)?,
        cost_usd: raw.cost_usd,
        cost_usd_exact: raw.cost_usd_exact,
    })
}

pub(crate) fn parse_taint_cwes_from_input(input: &Value) -> Result<Option<Vec<TaintCweSelection>>> {
    if let Some(value) = input.get("cwe").or_else(|| input.get("cwes")) {
        return parse_taint_cwes_value(value).map(Some);
    }
    Ok(None)
}

pub(crate) fn parse_taint_cwes_value(value: &Value) -> Result<Vec<TaintCweSelection>> {
    match value {
        Value::String(text) => Ok(parse_taint_cwe_text(text)),
        Value::Array(items) => parse_taint_cwe_array(items),
        _ => anyhow::bail!("taint-iris cwes must be a string or array"),
    }
}

fn parse_taint_cwe_text(text: &str) -> Vec<TaintCweSelection> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(operator_taint_cwe)
        .collect()
}

fn parse_taint_cwe_array(items: &[Value]) -> Result<Vec<TaintCweSelection>> {
    items
        .iter()
        .filter_map(nonempty_taint_cwe_item)
        .collect()
}

fn nonempty_taint_cwe_item(item: &Value) -> Option<Result<TaintCweSelection>> {
    match item {
        Value::String(id) if id.trim().is_empty() => None,
        Value::String(id) => Some(Ok(operator_taint_cwe(id.trim()))),
        Value::Object(object) => Some(parse_taint_cwe_object(object)),
        _ => Some(Err(anyhow::anyhow!(
            "taint-iris cwes must be a string, string array, or object array"
        ))),
    }
}

fn parse_taint_cwe_object(object: &Map<String, Value>) -> Result<TaintCweSelection> {
    let id = read_object_string(object, &["id", "cwe"])
        .context("taint-iris cwes entries require id or cwe")?;
    let name = read_object_string(object, &["name"]).unwrap_or_else(|| id.clone());
    let reason = read_object_string(object, &["reason"])
        .unwrap_or_else(|| "operator-supplied".to_string());
    Ok(TaintCweSelection { id, name, reason })
}

fn operator_taint_cwe(id: &str) -> TaintCweSelection {
    TaintCweSelection {
        id: id.to_string(),
        name: id.to_string(),
        reason: "operator-supplied".to_string(),
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
