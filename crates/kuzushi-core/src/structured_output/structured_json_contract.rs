use super::*;
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use std::fmt;

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

    /// Build a contract whose JSON schema is generated from a Rust type via
    /// `schemars`, so the canonical enum vocabularies (severity, confidence)
    /// are the single source of truth and drift is caught by schema tests.
    pub(crate) fn from_schema<T: schemars::JsonSchema>(
        tool_name: impl Into<String>,
        schema_name: impl Into<String>,
    ) -> Self {
        let schema = serde_json::to_value(schemars::schema_for!(T))
            .unwrap_or_else(|_| serde_json::json!({"type": "object"}));
        Self::new(tool_name, schema_name, schema)
    }

    pub(crate) fn runtime_contract(&self) -> AgentStructuredOutput {
        AgentStructuredOutput::json_schema(self.schema_name.clone(), self.schema.clone())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CostedStructuredJson<T> {
    pub(crate) value: T,
    /// Checked observed subtotal. Consult `cost_report` before presenting it
    /// as the complete provider cost.
    pub(crate) cost_usd: f64,
    pub(crate) cost_usd_exact: bool,
    /// Labelled local estimate for the unmetered part of an inexact cost.
    pub(crate) estimated_cost_usd: Option<f64>,
}

impl<T> CostedStructuredJson<T> {
    pub(crate) fn from_cost_report(value: T, cost: RuntimeCostReport) -> Self {
        Self {
            value,
            cost_usd: cost.observed_usd(),
            cost_usd_exact: cost.is_complete(),
            estimated_cost_usd: cost.unmetered_estimate_usd(),
        }
    }

    pub(crate) fn cost_report(&self) -> Result<RuntimeCostReport> {
        let observed = RuntimeCost::from_usd(self.cost_usd, "structured-output observed cost")?;
        if self.cost_usd_exact {
            return Ok(RuntimeCostReport::known(observed));
        }
        let estimate = self
            .estimated_cost_usd
            .map(|usd| RuntimeCost::from_usd(usd, "structured-output estimated cost"))
            .transpose()?;
        Ok(RuntimeCostReport::incomplete(observed).with_unmetered_estimate(estimate))
    }
}

/// Structured-output failure with the provider spend observed before the
/// failure. `provider_spend_unresolved` is true when a paid call failed before
/// returning usage, so callers must retain their conservative reservation.
#[derive(Debug)]
pub(crate) struct StructuredOutputError {
    source: anyhow::Error,
    cost: RuntimeCostReport,
    reason: FailureReason,
}

/// Which step failed, as an allowlisted operator label. Raw model or provider
/// text stays in the error chain for `{:#}` evidence, never in the message.
#[derive(Debug, Clone, Copy)]
enum FailureReason {
    Unspecified,
    ModelCall,
    ResponseRejected,
    Truncated,
    InvalidAfterRepair,
}

impl FailureReason {
    fn label(self) -> Option<&'static str> {
        match self {
            Self::Unspecified => None,
            Self::ModelCall => Some("model call failed"),
            Self::ResponseRejected => Some("model response could not be accepted"),
            Self::Truncated => Some("model response stopped before the JSON completed"),
            Self::InvalidAfterRepair => {
                Some("model output still violated the schema after one repair attempt")
            }
        }
    }
}

/// A repair the contract declined to send; no provider call was made, so the
/// initial call's cost stands unchanged.
#[derive(Debug)]
struct RepairRefused(&'static str);

impl fmt::Display for RepairRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "repair refused: {}", self.0)
    }
}

impl std::error::Error for RepairRefused {}

impl StructuredOutputError {
    pub(crate) fn from_source_and_cost(source: anyhow::Error, cost: RuntimeCostReport) -> Self {
        Self {
            source,
            cost,
            reason: FailureReason::Unspecified,
        }
    }

    /// The most specific cause that is safe to show: a declined repair, a
    /// typed runtime failure, or the failed step.
    fn safe_cause(&self) -> Option<String> {
        if let Some(refusal) = chain_find::<RepairRefused>(&self.source) {
            return Some(refusal.to_string());
        }
        if let Some(inner) = chain_find::<StructuredOutputError>(&self.source) {
            return inner.safe_cause();
        }
        if let Some(metadata) = crate::runtime::runtime_failure_metadata(&self.source) {
            return Some(runtime_failure_text(&metadata));
        }
        self.reason.label().map(str::to_string)
    }

    pub(crate) fn cost_report(&self) -> RuntimeCostReport {
        self.cost
    }
}

/// Raw provider text never reaches the message, but an allowlisted cause
/// does: "structured output failed" alone hid an unavailable MCP sidecar, a
/// refused repair, or a rejected request behind one parsing symptom.
impl fmt::Display for StructuredOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("structured output failed")?;
        match self.safe_cause() {
            Some(cause) => write!(formatter, ": {cause}"),
            None => Ok(()),
        }
    }
}

fn chain_find<E: std::error::Error + 'static>(error: &anyhow::Error) -> Option<&E> {
    error.chain().find_map(|source| source.downcast_ref::<E>())
}

fn runtime_failure_text(metadata: &crate::runtime::RuntimeFailureMetadata) -> String {
    let message = format!("{} ({})", metadata.public_message(), metadata.error_class);
    match &metadata.detail {
        Some(detail) => format!("{message} {detail}"),
        None => message,
    }
}

impl std::error::Error for StructuredOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
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
    let response = crate::runtime::query_blocking_checked(runtime, request.clone())
        .map_err(unknown_provider_failure)?;
    let repair_spend_stop = remaining_repair_spend_stop(&request, &response);
    parse_or_repair_required_structured_json_with_cost(
        response,
        contract,
        validate,
        |repair_prompt, output| {
            let remaining = repair_spend_stop?;
            let repair_request = repair_request_from(&request, repair_prompt, output);
            let repair_request = with_repair_spend_stop(repair_request, remaining);
            crate::runtime::query_blocking_checked(runtime, repair_request)
        },
    )
}

fn remaining_repair_spend_stop(
    request: &AgentQueryRequest,
    response: &AgentQueryResponse,
) -> Result<Option<f64>> {
    let stop = request
        .runtime_options
        .as_ref()
        .and_then(|options| options.observed_spend_stop_usd);
    let Some(stop) = stop else {
        return Ok(None);
    };
    // Unmetered spend counts at its labelled estimate; with no estimate the
    // remaining budget is unknown and the repair is refused.
    let spent = response
        .checked_cost_report()?
        .estimated_total_usd()
        .ok_or(RepairRefused(
            "the initial call has neither a spend receipt nor an estimate",
        ))?;
    let remaining = stop - spent;
    if remaining <= 0.0 {
        return Err(RepairRefused("the observed spend stop is exhausted").into());
    }
    Ok(Some(remaining))
}

fn with_repair_spend_stop(
    mut request: AgentQueryRequest,
    remaining: Option<f64>,
) -> AgentQueryRequest {
    if let Some(options) = request.runtime_options.as_mut() {
        options.observed_spend_stop_usd = remaining;
    }
    request
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
    repair_request.thinking_level = request.thinking_level.clone();
    repair_request.stage = request.stage.clone();
    repair_request.max_output_tokens = request.max_output_tokens;
    repair_request.runtime_options = request.runtime_options.clone();
    repair_request.temperature = request.temperature;
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
    let initial_cost = checked_response_cost(&response, RuntimeCostReport::INCOMPLETE_ZERO)?;
    let initial_material = checked_response_material(&response, initial_cost)?;
    reject_truncated_response(&response, &contract, &initial_material, initial_cost)?;
    match parse_and_validate_measured(&response, &contract, &validate) {
        Ok(value) => Ok(CostedStructuredJson::from_cost_report(value, initial_cost)),
        Err(initial_error) => repair_structured_json_response(
            initial_material,
            &contract,
            &validate,
            repair,
            initial_cost,
            initial_error,
        ),
    }
}

fn repair_structured_json_response<T>(
    initial_material: ResponseMaterial,
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
    repair: impl FnOnce(String, AgentStructuredOutput) -> Result<AgentQueryResponse>,
    initial_cost: RuntimeCostReport,
    initial_error: anyhow::Error,
) -> Result<CostedStructuredJson<T>> {
    let repair_prompt = build_repair_prompt(contract, &initial_material, &initial_error)
        .map_err(|error| observed_failure(error, initial_cost, FailureReason::ResponseRejected))?;
    let repair_response = repair(repair_prompt, contract.runtime_contract())
        .map_err(|error| repair_call_failure(error, initial_cost))?;
    parse_repaired_response(
        contract,
        validate,
        initial_cost,
        initial_error,
        initial_material,
        repair_response,
    )
}

fn reject_truncated_response(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
    material: &ResponseMaterial,
    cost: RuntimeCostReport,
) -> Result<()> {
    if !response.truncated {
        return Ok(());
    }
    let cause = anyhow::anyhow!("response stopped before natural structured-output completion");
    let error = truncation_error(contract, response, &cause, material)
        .context("Could not render bounded structured-output truncation evidence")
        .map_err(|error| observed_failure(error, cost, FailureReason::Truncated))?;
    Err(observed_failure(error, cost, FailureReason::Truncated))
}

fn parse_repaired_response<T>(
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
    initial_cost: RuntimeCostReport,
    initial_error: anyhow::Error,
    initial_material: ResponseMaterial,
    repair_response: AgentQueryResponse,
) -> Result<CostedStructuredJson<T>> {
    let repair_cost = checked_response_cost(&repair_response, initial_cost)?;
    let total_cost = initial_cost
        .checked_add(repair_cost, "structured-output initial plus repair cost")
        .map_err(|error| unresolved_provider_failure(error, initial_cost))?;
    let repair_material = checked_response_material(&repair_response, total_cost)?;
    if repair_response.truncated {
        let error = truncation_error(contract, &repair_response, &initial_error, &repair_material)
            .context("Could not render bounded structured-output truncation evidence")
            .map_err(|error| observed_failure(error, total_cost, FailureReason::Truncated))?;
        return Err(observed_failure(
            error,
            total_cost,
            FailureReason::Truncated,
        ));
    }
    match parse_and_validate_measured(&repair_response, contract, validate) {
        Ok(value) => Ok(CostedStructuredJson::from_cost_report(value, total_cost)),
        Err(repair_error) => {
            let error = repair_failure_error(
                contract,
                &initial_error,
                &initial_material,
                &repair_error,
                &repair_material,
            )
            .context("Could not render bounded structured-output repair evidence")
            .map_err(|error| observed_failure(error, total_cost, INVALID))?;
            Err(observed_failure(error, total_cost, INVALID))
        }
    }
}

fn checked_response_material(
    response: &AgentQueryResponse,
    observed_cost: RuntimeCostReport,
) -> Result<ResponseMaterial> {
    let material = ResponseMaterial::from_response(response)
        .map_err(|error| observed_failure(error, observed_cost, FailureReason::ResponseRejected))?;
    material
        .ensure_within_budget()
        .map_err(|error| observed_failure(error, observed_cost, FailureReason::ResponseRejected))?;
    Ok(material)
}

fn checked_response_cost(
    response: &AgentQueryResponse,
    observed_cost: RuntimeCostReport,
) -> Result<RuntimeCostReport> {
    response
        .checked_cost_report()
        .map_err(|error| unresolved_provider_failure(error, observed_cost))
}

#[cfg(test)]
mod observed_spend_stop_tests {
    use super::*;

    fn request(stop_usd: f64) -> AgentQueryRequest {
        AgentQueryRequest::new("openai:test", ".", "system", "prompt").with_runtime_options(
            crate::runtime::AgentRuntimeOptions {
                observed_spend_stop_usd: Some(stop_usd),
                ..Default::default()
            },
        )
    }

    #[test]
    fn structured_repair_requires_exact_remaining_spend() {
        let incomplete = AgentQueryResponse {
            cost_usd: 0.10,
            cost_usd_reported: false,
            ..Default::default()
        };
        let exhausted = AgentQueryResponse {
            cost_usd: 0.25,
            cost_usd_reported: true,
            ..Default::default()
        };

        assert!(remaining_repair_spend_stop(&request(1.0), &incomplete).is_err());
        assert!(remaining_repair_spend_stop(&request(0.25), &exhausted).is_err());
    }

    #[test]
    fn structured_repair_receives_only_the_exact_remaining_stop() {
        let response = AgentQueryResponse {
            cost_usd: 0.10,
            cost_usd_reported: true,
            ..Default::default()
        };

        let remaining = remaining_repair_spend_stop(&request(0.25), &response).unwrap();

        assert!((remaining.unwrap() - 0.15).abs() < f64::EPSILON);
    }
}

fn unknown_provider_failure(error: anyhow::Error) -> anyhow::Error {
    unresolved_provider_failure(error, RuntimeCostReport::INCOMPLETE_ZERO)
}

fn unresolved_provider_failure(
    source: anyhow::Error,
    observed_cost: RuntimeCostReport,
) -> anyhow::Error {
    StructuredOutputError {
        source,
        cost: observed_cost.mark_incomplete(),
        reason: FailureReason::ModelCall,
    }
    .into()
}

/// A declined repair made no call, so the initial cost stands; any other
/// repair failure may have spent without a receipt.
fn repair_call_failure(error: anyhow::Error, initial_cost: RuntimeCostReport) -> anyhow::Error {
    if chain_find::<RepairRefused>(&error).is_some() {
        return observed_failure(error, initial_cost, FailureReason::ModelCall);
    }
    unresolved_provider_failure(error, initial_cost)
}

const INVALID: FailureReason = FailureReason::InvalidAfterRepair;

fn observed_failure(
    source: anyhow::Error,
    observed_cost: RuntimeCostReport,
    reason: FailureReason,
) -> anyhow::Error {
    StructuredOutputError {
        source,
        cost: observed_cost,
        reason,
    }
    .into()
}

fn parse_and_validate_measured<T>(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
    validate: &impl Fn(Value) -> Result<T>,
) -> Result<T> {
    let value = structured_json_value_measured(response, contract)?;
    validate(value)
}

fn structured_json_value_measured(
    response: &AgentQueryResponse,
    contract: &StructuredJsonContract,
) -> Result<Value> {
    if let Some(value) = response.structured.clone() {
        return Ok(value);
    }
    parse_json_value_from_agent_text_with_strategy(&response.text)
        .map(|parsed| parsed.value)
        .with_context(|| {
            format!(
                "{} expected LangGraph to return JSON for `{}`",
                contract.tool_name, contract.schema_name
            )
        })
}

#[cfg(test)]
mod structured_output_error_message_tests {
    use super::*;
    use crate::runtime::{RuntimeFailure, RuntimeFailureClass, RuntimeFailureMetadata};

    #[test]
    fn a_typed_runtime_cause_is_named_and_raw_text_is_not() {
        let metadata = RuntimeFailureMetadata::new(RuntimeFailureClass::McpUnavailable, None, None);
        let source = anyhow::Error::new(RuntimeFailure::new(metadata))
            .context("raw-provider-sentinel body text");
        let error = unknown_provider_failure(source);

        let message = error.to_string();
        assert!(
            message.starts_with("structured output failed: Restore the missing"),
            "{message}"
        );
        assert!(message.contains("(mcp_unavailable)"), "{message}");
        assert!(message.contains("cargo build --workspace"), "{message}");
        assert!(!message.contains("raw-provider-sentinel"), "{message}");
    }

    #[test]
    fn an_untyped_cause_names_only_the_failed_step() {
        let error = unknown_provider_failure(anyhow::anyhow!("raw-provider-sentinel"));
        assert_eq!(
            error.to_string(),
            "structured output failed: model call failed"
        );
    }

    #[test]
    fn a_refused_repair_keeps_the_initial_estimate_and_says_why() {
        let estimate = crate::runtime::RuntimeCost::from_usd(0.2, "cost").unwrap();
        let initial = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(estimate));
        let refused = anyhow::Error::from(RepairRefused("the observed spend stop is exhausted"));

        let error = repair_call_failure(refused, initial);

        assert_eq!(
            error.to_string(),
            "structured output failed: repair refused: the observed spend stop is exhausted"
        );
        let cost = error
            .downcast_ref::<StructuredOutputError>()
            .unwrap()
            .cost_report();
        assert_eq!(cost.estimated_total_usd(), Some(0.2));
    }

    #[test]
    fn estimated_initial_spend_leaves_repair_budget() {
        let request = AgentQueryRequest::new("anthropic:claude-haiku-4-5", ".", "s", "p")
            .with_runtime_options(crate::runtime::AgentRuntimeOptions {
                observed_spend_stop_usd: Some(1.0),
                ..Default::default()
            });
        let estimated = AgentQueryResponse {
            estimated_cost_usd: Some(0.25),
            ..Default::default()
        };
        let remaining = remaining_repair_spend_stop(&request, &estimated).unwrap();
        assert_eq!(remaining, Some(0.75));

        let unpriced = AgentQueryResponse::default();
        let error = remaining_repair_spend_stop(&request, &unpriced).unwrap_err();
        assert!(error
            .to_string()
            .contains("neither a spend receipt nor an estimate"));
    }
}
