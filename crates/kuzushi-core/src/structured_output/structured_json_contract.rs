use super::*;

#[derive(Debug, Clone)]
pub(crate) struct StructuredJsonContract {
    pub(crate) tool_name: String,
    pub(crate) schema_name: String,
    pub(crate) schema: Value,
}

impl StructuredJsonContract {
    pub(crate) fn new(
        tool_name: impl Into<String>,
        schema_name: impl Into<String>,
        schema: Value,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            schema_name: schema_name.into(),
            schema,
        }
    }

    pub(crate) fn runtime_contract(&self) -> AgentStructuredOutput {
        AgentStructuredOutput::json_schema(self.schema_name.clone(), self.schema.clone())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CostedStructuredJson<T> {
    pub(crate) value: T,
    pub(crate) cost_usd: f64,
}

pub(crate) fn query_required_structured_json<T>(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
) -> Result<T> {
    Ok(query_required_structured_json_with_cost(runtime, request, contract, validate)?.value)
}

pub(crate) fn query_required_structured_json_with_cost<T>(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
) -> Result<CostedStructuredJson<T>> {
    let request = request.with_structured_output(contract.runtime_contract());
    let response = runtime.query_blocking(request.clone())?;
    parse_or_repair_required_structured_json_with_cost(
        response,
        contract,
        validate,
        |repair_prompt, output| {
            let repair_request = repair_request_from(&request, repair_prompt, output);
            runtime.query_blocking(repair_request)
        },
    )
}

pub(crate) fn repair_request_from(
    request: &AgentQueryRequest,
    repair_prompt: String,
    output: AgentStructuredOutput,
) -> AgentQueryRequest {
    let mut repair_request = AgentQueryRequest::new(
        request.model.clone(),
        request.cwd.clone(),
        request.system_prompt.clone(),
        repair_prompt,
    )
    .with_tool_policy(request.tool_policy.clone())
    .with_structured_output(output);
    if let Some(thinking_level) = request.thinking_level.clone() {
        repair_request = repair_request.with_thinking_level(thinking_level);
    }
    if let Some(max_output_tokens) = request.max_output_tokens {
        repair_request = repair_request.with_max_output_tokens(max_output_tokens);
    }
    repair_request
}

#[cfg(test)]
pub(crate) fn parse_or_repair_required_structured_json<T>(
    response: AgentQueryResponse,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
) -> Result<T> {
    Ok(
        parse_or_repair_required_structured_json_with_cost(response, contract, validate, repair)?
            .value,
    )
}

pub(crate) fn parse_or_repair_required_structured_json_with_cost<T>(
    response: AgentQueryResponse,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
) -> Result<CostedStructuredJson<T>> {
    let initial_cost = response.cost_usd;
    match parse_and_validate(&response, &contract, &validate) {
        Ok(value) => Ok(CostedStructuredJson {
            value,
            cost_usd: initial_cost,
        }),
        Err(initial_error) => repair_structured_json_response(
            response,
            &contract,
            &validate,
            repair,
            initial_cost,
            initial_error,
        ),
    }
}

fn repair_structured_json_response<T>(
    response: AgentQueryResponse,
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
    initial_cost: f64,
    initial_error: anyhow::Error,
) -> Result<CostedStructuredJson<T>> {
    if response.truncated {
        return Err(truncation_error(contract, &response, &initial_error));
    }
    let raw = raw_agent_response(&response);
    let repair_response = repair(
        build_repair_prompt(contract, &raw, &initial_error.to_string()),
        contract.runtime_contract(),
    )?;
    parse_repaired_response(
        contract,
        validate,
        initial_cost,
        initial_error,
        raw,
        repair_response,
    )
}

fn parse_repaired_response<T>(
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
    initial_cost: f64,
    initial_error: anyhow::Error,
    raw: String,
    repair_response: AgentQueryResponse,
) -> Result<CostedStructuredJson<T>> {
    if repair_response.truncated {
        return Err(truncation_error(contract, &repair_response, &initial_error));
    }
    let repair_cost = repair_response.cost_usd;
    let value = parse_and_validate(&repair_response, contract, validate).with_context(|| {
        repair_failure_message(contract, &initial_error, &raw, &repair_response)
    })?;
    Ok(CostedStructuredJson {
        value,
        cost_usd: initial_cost + repair_cost,
    })
}

fn repair_failure_message(
    contract: &StructuredJsonContract,
    initial_error: &anyhow::Error,
    raw: &str,
    repair_response: &AgentQueryResponse,
) -> String {
    let repair_raw = raw_agent_response(repair_response);
    format!(
        "{tool} could not satisfy structured JSON contract `{schema}` after one repair pass.\n\
         Initial parse/validation failure: {initial_error}\n\
         Repair parse/validation failure is above.\n\
         Raw initial model response:\n{raw}\n\
         Raw repair model response:\n{repair_raw}",
        tool = contract.tool_name,
        schema = contract.schema_name,
    )
}

fn truncation_error(
    contract: &StructuredJsonContract,
    response: &AgentQueryResponse,
    initial_error: &anyhow::Error,
) -> anyhow::Error {
    let raw = raw_agent_response(response);
    let stop_reason = response.stop_reason.as_deref().unwrap_or("length");
    anyhow::anyhow!(
        "{tool} response was truncated by the per-call output-token cap \
         (stopReason: {stop_reason:?}); the partial JSON cannot satisfy \
         contract `{schema}`. Remediation: raise `AgentQueryRequest::max_output_tokens` \
         (or set `maxOutputTokens` in the tool input), reduce the requested output \
         size such as `maxFindings`, or shorten the prompt. \
         Initial parse/validation failure: {initial_error}\n\
         Raw partial response (truncated):\n{raw}",
        tool = contract.tool_name,
        schema = contract.schema_name,
    )
}

pub(crate) fn parse_and_validate<T>(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
) -> Result<T> {
    let value = structured_json_value(response, contract)?;
    validate(value)
}

pub(crate) fn structured_json_value(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
) -> Result<Value> {
    if let Some(value) = response.structured.clone() {
        return Ok(value);
    }
    parse_json_value_from_agent_text(&response.text).with_context(|| {
        format!(
            "{} expected LangGraph to return JSON for `{}`",
            contract.tool_name, contract.schema_name
        )
    })
}
