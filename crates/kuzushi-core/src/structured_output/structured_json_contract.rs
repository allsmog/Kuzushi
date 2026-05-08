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

pub(crate) fn query_required_structured_json<T>(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
) -> Result<T> {
    let request = request.with_structured_output(contract.runtime_contract());
    let response = runtime.query_blocking(request.clone())?;
    parse_or_repair_required_structured_json(
        response,
        contract,
        validate,
        |repair_prompt, output| {
            runtime.query_blocking(
                AgentQueryRequest::new(
                    request.model.clone(),
                    request.cwd.clone(),
                    request.system_prompt.clone(),
                    repair_prompt,
                )
                .with_tool_policy(request.tool_policy.clone())
                .with_structured_output(output),
            )
        },
    )
}

pub(crate) fn parse_or_repair_required_structured_json<T>(
    response: AgentQueryResponse,
    contract: StructuredJsonContract,
    validate: impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
) -> Result<T> {
    match parse_and_validate(&response, &contract, &validate) {
        Ok(value) => Ok(value),
        Err(initial_error) => {
            let raw = raw_agent_response(&response);
            let repair_response = repair(
                build_repair_prompt(&contract, &raw, &initial_error.to_string()),
                contract.runtime_contract(),
            )?;
            parse_and_validate(&repair_response, &contract, &validate).with_context(|| {
                let repair_raw = raw_agent_response(&repair_response);
                format!(
                    "{tool} could not satisfy structured JSON contract `{schema}` after one repair pass.\n\
                     Initial parse/validation failure: {initial_error}\n\
                     Repair parse/validation failure is above.\n\
                     Raw initial model response:\n{raw}\n\
                     Raw repair model response:\n{repair_raw}",
                    tool = contract.tool_name,
                    schema = contract.schema_name,
                )
            })
        }
    }
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
            "{} expected pi-agent-core to return JSON for `{}`",
            contract.tool_name, contract.schema_name
        )
    })
}
