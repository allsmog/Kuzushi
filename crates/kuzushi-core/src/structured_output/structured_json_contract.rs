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
    let response = if response.truncated {
        match retry_with_higher_output_budget(runtime, &request) {
            Ok(retry_response) => retry_response,
            Err(_) => response,
        }
    } else {
        response
    };
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

fn retry_with_higher_output_budget(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
) -> Result<AgentQueryResponse> {
    const RETRY_FLOOR: u32 = 16_000;
    const RETRY_CEILING: u32 = 65_535;
    let next_budget = match request.max_output_tokens {
        Some(cap) if cap >= RETRY_CEILING => cap,
        Some(cap) => cap.saturating_mul(2).clamp(RETRY_FLOOR, RETRY_CEILING),
        None => RETRY_FLOOR,
    };
    runtime.query_blocking(request.clone().with_max_output_tokens(next_budget))
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
        Err(initial_error) => {
            if response.truncated {
                return Err(truncation_error(&contract, &response, &initial_error));
            }
            let raw = raw_agent_response(&response);
            let repair_response = repair(
                build_repair_prompt(&contract, &raw, &initial_error.to_string()),
                contract.runtime_contract(),
            )?;
            if repair_response.truncated {
                return Err(truncation_error(
                    &contract,
                    &repair_response,
                    &initial_error,
                ));
            }
            let repair_cost = repair_response.cost_usd;
            let value =
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
            })?;
            Ok(CostedStructuredJson {
                value,
                cost_usd: initial_cost + repair_cost,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::TriageOutcome;
    use crate::runtime::TriageRequest;
    use std::sync::Mutex;

    struct CapturingRuntime {
        tokens: Mutex<Vec<Option<u32>>>,
    }

    impl CapturingRuntime {
        fn new() -> Self {
            Self {
                tokens: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for CapturingRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            self.tokens.lock().unwrap().push(request.max_output_tokens);
            Ok(AgentQueryResponse::default())
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("not used by structured output tests")
        }
    }

    #[test]
    fn retry_budget_raises_missing_small_and_capped_requests() {
        let runtime = CapturingRuntime::new();
        let base = AgentQueryRequest::new("model", ".", "system", "prompt");

        retry_with_higher_output_budget(&runtime, &base).unwrap();
        retry_with_higher_output_budget(&runtime, &base.clone().with_max_output_tokens(4_000))
            .unwrap();
        retry_with_higher_output_budget(&runtime, &base.with_max_output_tokens(65_535)).unwrap();

        let tokens = runtime.tokens.lock().unwrap().clone();
        assert_eq!(tokens, vec![Some(16_000), Some(16_000), Some(65_535)]);
    }
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
            "{} expected pi-agent-core to return JSON for `{}`",
            contract.tool_name, contract.schema_name
        )
    })
}
