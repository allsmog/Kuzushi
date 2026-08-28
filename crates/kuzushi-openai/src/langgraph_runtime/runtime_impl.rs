use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_core::{
    runtime::RuntimeCostReport, AgentLoopStep, AgentQueryControl, AgentQueryRequest,
    AgentQueryResponse, AgentRuntime, AgentStructuredOutput, AgentToolLoopRequest,
    AgentToolPolicyAuthorization, AgentToolPolicyReceipt, LoopHistoryEntry, ModelTokenUsage,
    Observed, RuntimeFailure, RuntimeFailureClass, RuntimeFailureMetadata, ScanCancellation,
    TriageOutcome, TriageRequest,
};

use super::bridge_payloads::{
    BridgeRequest, BridgeResponse, PingBridgeRequest, PingBridgeResponse,
    ToolPolicyHandshakeBridgeRequest, ToolPolicyHandshakeBridgeResponse,
    LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
};
use super::bridge_process::{
    bridge_runtime_failure, run_bridge, run_strict_json_bridge, run_tool_policy_handshake_bridge,
};
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::next_step_bridge::next_step_observed_blocking as run_next_step_observed_blocking;
use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
use super::runtime_config::LangGraphRuntime;
use super::transport_retry;
use super::triage::{
    clamp_outcome, normalize_triage_confidence, triage_prompt, triage_system_prompt,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn clamp_token_count_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[async_trait]
impl AgentRuntime for LangGraphRuntime {
    fn preflight_model_blocking(&self, model: &str) -> Result<()> {
        self.validated_model_credential(model).map(|_| ())
    }

    fn authorize_tool_policy_blocking(
        &self,
        authorization: &AgentToolPolicyAuthorization,
    ) -> Result<AgentToolPolicyReceipt> {
        let request = ToolPolicyHandshakeBridgeRequest {
            protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
            envelope_type: "tool-policy-handshake",
            authorization: authorization.clone(),
        };
        let response = run_tool_policy_handshake_bridge(&self.command, &request)?;
        tool_policy_receipt(response, authorization)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let (response, model) = self.run_query_bridge(request, None)?;
        observed_agent_response_from_bridge(response, &model)?
            .try_map(AgentQueryResponse::validate_cost)
    }

    fn query_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<AgentQueryResponse> {
        self.query_observed_blocking_controlled(request, control)
            .map(Observed::into_value)
    }

    fn query_observed_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<Observed<AgentQueryResponse>> {
        control.ensure_active()?;
        let local = ScanCancellation::default();
        let done = Arc::new(AtomicBool::new(false));
        let watchdog = spawn_query_control_watchdog(
            local.clone(),
            self.cancellation.clone(),
            control.clone(),
            Arc::clone(&done),
        );
        let result = self
            .clone()
            .with_cancellation(local)
            .query_observed_blocking(request);
        done.store(true, Ordering::SeqCst);
        let _ = watchdog.join();
        control.ensure_active()?;
        result
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_observed_blocking(
            AgentQueryRequest::new(request.model, request.cwd, triage_system_prompt(), prompt)
                .with_structured_output(triage_structured_output())
                .with_temperature(0.0),
        )?;
        response.try_map(triage_outcome_from_response)
    }

    fn supports_tools(&self) -> bool {
        // Anthropic-only in this version (bridge enforces). Routed
        // queries with non-Anthropic models will surface a clear error
        // from the bridge itself.
        true
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        run_next_step_blocking(self, request, history)
    }

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        run_next_step_observed_blocking(self, request, history)
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        run_preflight_tool_loop_blocking(self, request)
    }
}

fn tool_policy_receipt(
    response: ToolPolicyHandshakeBridgeResponse,
    authorization: &AgentToolPolicyAuthorization,
) -> Result<AgentToolPolicyReceipt> {
    if !response.ok {
        return Err(bridge_runtime_failure(
            response.error_class.as_deref(),
            response.status,
            response.error.as_deref(),
            response.detail.as_deref(),
        ));
    }
    let receipt = response
        .acknowledgement
        .context("Ask bridge omitted its tool-policy acknowledgement")?;
    receipt.validate_for(authorization)?;
    Ok(receipt)
}

fn execution_tool_policy_receipt(
    response: &BridgeResponse,
    authorization: &AgentToolPolicyAuthorization,
) -> Result<AgentToolPolicyReceipt> {
    let receipt = response
        .tool_policy_acknowledgement
        .clone()
        .context("executing Ask bridge omitted its tool-policy acknowledgement")?;
    receipt.validate_for(authorization)?;
    Ok(receipt)
}

#[cfg(test)]
mod tool_policy_receipt_tests {
    use super::*;

    fn authorization() -> AgentToolPolicyAuthorization {
        let target = tempfile::tempdir().unwrap();
        AgentToolPolicyAuthorization::read_only_ask(target.path()).unwrap()
    }

    fn response(
        acknowledgement: Option<AgentToolPolicyReceipt>,
    ) -> ToolPolicyHandshakeBridgeResponse {
        ToolPolicyHandshakeBridgeResponse {
            ok: true,
            acknowledgement,
            error: None,
            error_class: None,
            detail: None,
            status: None,
        }
    }

    #[test]
    fn missing_bridge_acknowledgement_fails_closed() {
        let error = tool_policy_receipt(response(None), &authorization())
            .unwrap_err()
            .to_string();

        assert!(error.contains("omitted its tool-policy acknowledgement"));
    }

    #[test]
    fn mismatched_effective_tools_fail_closed() {
        let authorization = authorization();
        let receipt = AgentToolPolicyReceipt {
            protocol_version: authorization.protocol_version,
            policy_id: authorization.policy_id.clone(),
            effective_tools: vec!["Read".to_string(), "Write".to_string()],
            read_roots: authorization.policy.mcp_read_roots.clone(),
            write_shell_tools_mounted: true,
            mcp_tools_mounted: false,
        };

        assert!(tool_policy_receipt(response(Some(receipt)), &authorization).is_err());
    }

    #[test]
    fn executing_query_without_acknowledgement_fails_closed() {
        let response: BridgeResponse = serde_json::from_value(serde_json::json!({
            "ok": true,
            "text": "answer",
            "structured": null,
            "error": null
        }))
        .unwrap();

        let error = execution_tool_policy_receipt(&response, &authorization())
            .unwrap_err()
            .to_string();

        assert!(error.contains("executing Ask bridge omitted"));
    }

    #[test]
    fn authorized_query_returns_receipt_from_its_executing_process() {
        let target = tempfile::tempdir().unwrap();
        let authorization = AgentToolPolicyAuthorization::read_only_ask(target.path()).unwrap();
        let script = r#"let b='';process.stdin.on('data',c=>b+=c);process.stdin.on('end',()=>{let r=JSON.parse(b),a=r.authorization;process.stdout.write(JSON.stringify({ok:true,text:'bound',structured:null,error:null,toolPolicyAcknowledgement:{protocolVersion:a.protocolVersion,policyId:a.policyId,effectiveTools:a.policy.tools,readRoots:a.policy.mcpReadRoots,writeShellToolsMounted:false,mcpToolsMounted:false}}))})"#;
        let config = kuzushi_core::RuntimeConfig {
            api_key_env: "OPENAI_API_KEY".to_string(),
            langgraph_bridge_command: Some(vec![
                "node".to_string(),
                "-e".to_string(),
                script.to_string(),
            ]),
            ..kuzushi_core::RuntimeConfig::default()
        };
        let runtime = LangGraphRuntime::from_runtime_config(&config, target.path()).unwrap();
        let request =
            AgentQueryRequest::new("openai:gpt-test", target.path(), "system", "question")
                .with_tool_policy(authorization.policy.clone());

        let (response, receipt) = runtime
            .query_authorized_observed_blocking(request, &authorization)
            .unwrap();

        assert_eq!(response.value.text, "bound");
        assert_eq!(
            receipt,
            AgentToolPolicyReceipt {
                protocol_version: kuzushi_core::runtime::READ_ONLY_ASK_POLICY_PROTOCOL_VERSION,
                policy_id: kuzushi_core::runtime::READ_ONLY_ASK_POLICY_ID.to_string(),
                effective_tools: kuzushi_core::runtime::READ_ONLY_ASK_TOOLS
                    .iter()
                    .map(|tool| (*tool).to_string())
                    .collect(),
                read_roots: vec![target.path().canonicalize().unwrap()],
                write_shell_tools_mounted: false,
                mcp_tools_mounted: false,
            }
        );
    }
}

fn bridge_request_from(
    runtime: &LangGraphRuntime,
    request: AgentQueryRequest,
    credential: ModelCredential,
    authorization: Option<AgentToolPolicyAuthorization>,
) -> BridgeRequest {
    let thinking_level = request
        .thinking_level
        .or_else(|| runtime.thinking_level.clone());
    BridgeRequest {
        protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
        model: request.model,
        cwd: request.cwd.display().to_string(),
        system_prompt: request.system_prompt,
        prompt: request.prompt,
        structured_output: request.structured_output,
        api_key_env: credential.env,
        api_key: credential.value,
        oauth_credentials_path: runtime.oauth_credentials_path.display().to_string(),
        oauth_allow_env_token: runtime.oauth_allow_env_token,
        base_url: runtime.base_url.clone(),
        thinking_level,
        max_output_tokens: request.max_output_tokens,
        tool_policy: request.tool_policy,
        authorization,
        runtime_options: request.runtime_options,
        temperature: request.temperature,
    }
}

fn observed_agent_response_from_bridge(
    response: BridgeResponse,
    model: &str,
) -> Result<Observed<AgentQueryResponse>> {
    let usage = bridge_model_usage(&response)?;
    let (cost_usd, cost_usd_reported) = bridge_cost(&response)?;
    let estimated_cost_usd = estimated_bridge_cost(&response, model);
    Ok(Observed::new(
        AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            cost_usd,
            cost_usd_reported,
            estimated_cost_usd,
            input_tokens: clamp_token_count_u32(response.input_tokens.unwrap_or(0)),
            output_tokens: clamp_token_count_u32(response.output_tokens.unwrap_or(0)),
            truncated: response.truncated,
            stop_reason: response.stop_reason,
        },
        usage,
    ))
}

pub(super) fn estimated_bridge_cost(response: &BridgeResponse, model: &str) -> Option<f64> {
    if response.cost_usd.is_some() {
        return None;
    }
    crate::anthropic_oauth::estimate_cost_usd(
        model,
        clamp_token_count_u32(response.input_tokens?),
        clamp_token_count_u32(response.output_tokens?),
    )
}

fn bridge_model_usage(response: &BridgeResponse) -> Result<ModelTokenUsage> {
    let Some(total_calls) = response.model_calls else {
        return Ok(ModelTokenUsage::from_reported_options(
            response.input_tokens,
            response.output_tokens,
        ));
    };
    ModelTokenUsage::from_aggregate(
        response.input_tokens,
        response.output_tokens,
        response
            .input_reported_calls
            .context("bridge omitted input reported-call count")?,
        response
            .output_reported_calls
            .context("bridge omitted output reported-call count")?,
        total_calls,
    )
}

fn bridge_cost(response: &BridgeResponse) -> Result<(f64, bool)> {
    let Some(total_calls) = response.model_calls else {
        return Ok((
            response.cost_usd.unwrap_or(0.0),
            response.cost_usd.is_some(),
        ));
    };
    let reported_calls = response
        .cost_reported_calls
        .context("bridge omitted cost reported-call count")?;
    anyhow::ensure!(
        reported_calls <= total_calls,
        "bridge cost provenance exceeds model calls"
    );
    anyhow::ensure!(
        response.cost_usd.is_some() == (reported_calls > 0),
        "bridge cost total and reported-call provenance disagree"
    );
    let exact = response
        .cost_usd_exact
        .context("bridge omitted cost exactness")?;
    anyhow::ensure!(
        exact == (reported_calls == total_calls),
        "bridge cost exactness disagrees with provenance"
    );
    Ok((response.cost_usd.unwrap_or(0.0), exact))
}

fn spawn_query_control_watchdog(
    local: ScanCancellation,
    existing: Option<ScanCancellation>,
    control: AgentQueryControl,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if control.is_cancelled()
                || control.is_expired()
                || existing
                    .as_ref()
                    .is_some_and(ScanCancellation::is_cancelled)
            {
                local.cancel();
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
    })
}

pub(crate) struct ModelCredential {
    pub(crate) env: String,
    pub(crate) value: Option<String>,
}

impl LangGraphRuntime {
    pub fn query_authorized_observed_blocking(
        &self,
        request: AgentQueryRequest,
        authorization: &AgentToolPolicyAuthorization,
    ) -> Result<(Observed<AgentQueryResponse>, AgentToolPolicyReceipt)> {
        let (response, model) = self.run_query_bridge(request, Some(authorization.clone()))?;
        let receipt = execution_tool_policy_receipt(&response, authorization)?;
        let observed = observed_agent_response_from_bridge(response, &model)?
            .try_map(AgentQueryResponse::validate_cost)?;
        Ok((observed, receipt))
    }

    fn run_query_bridge(
        &self,
        request: AgentQueryRequest,
        authorization: Option<AgentToolPolicyAuthorization>,
    ) -> Result<(BridgeResponse, String)> {
        let model = request.model.clone();
        let credential = self.credential_for_model(&request.model)?;
        let request = bridge_request_from(self, request, credential, authorization);
        let response = run_bridge_with_transport_retries(
            &self.command,
            request,
            self.cancellation.as_ref(),
            &self.retry,
        )?;
        Ok((response, model))
    }

    pub(crate) fn credential_for_model(&self, model: &str) -> Result<ModelCredential> {
        let env = kuzushi_core::runtime::bridge_api_key_env_for_model(model, &self.api_key_env)?;
        let value = if env == self.api_key_env {
            self.api_key.clone()
        } else {
            std::env::var(&env)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Ok(ModelCredential { env, value })
    }

    pub(crate) fn validated_model_credential(&self, model: &str) -> Result<ModelCredential> {
        let credential = self.credential_for_model(model)?;
        let provider = model
            .split_once(':')
            .map(|(provider, _)| provider)
            .unwrap_or("");
        let ready = match provider {
            "openai" => credential.value.is_some(),
            "openai-codex" => oauth_is_ready(crate::oauth::probe_openai_path(
                &self.oauth_credentials_path,
            )?),
            "anthropic" => {
                credential.value.is_some()
                    || (self.oauth_allow_env_token && crate::oauth::has_env_token())
                    || oauth_is_ready(crate::oauth::probe_path(&self.oauth_credentials_path)?)
            }
            // Vertex resolves Application Default Credentials and project
            // identity inside the SDK, including workload metadata identities.
            "vertex-anthropic" => true,
            _ => false,
        };
        if ready {
            return Ok(credential);
        }
        Err(missing_model_credential(model, provider))
    }

    /// One-token credential round-trip for `auth ping`.
    ///
    /// The credential comes from the model's own provider, so a mismatched
    /// request fails here — before a bridge process exists — instead of
    /// forwarding one provider's secret to another. A nonzero bridge exit is
    /// a failure even if the bridge printed a success document.
    pub fn auth_ping_blocking(&self, model: &str) -> Result<PingBridgeResponse> {
        let model = kuzushi_core::runtime::canonical_model_spec(model)?;
        let credential = self.validated_model_credential(&model)?;
        let request = self.ping_request(model, credential);
        run_strict_json_bridge(
            &self.command,
            &request,
            "auth ping bridge",
            self.cancellation.as_ref(),
        )
    }

    fn ping_request(&self, model: String, credential: ModelCredential) -> PingBridgeRequest {
        PingBridgeRequest {
            protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
            envelope_type: "ping",
            model,
            api_key_env: credential.env,
            api_key: credential.value,
            oauth_credentials_path: self.oauth_credentials_path.display().to_string(),
            oauth_allow_env_token: self.oauth_allow_env_token,
            base_url: self.base_url.clone(),
        }
    }
}

fn oauth_is_ready(readiness: crate::oauth::OauthReadiness) -> bool {
    matches!(
        readiness,
        crate::oauth::OauthReadiness::Ready { .. } | crate::oauth::OauthReadiness::Expired { .. }
    )
}

fn missing_model_credential(model: &str, provider: &str) -> anyhow::Error {
    let guidance = match provider {
        "openai" => format!(
            "{model} requires OPENAI_API_KEY; stored OpenAI OAuth works only with openai-codex models"
        ),
        "openai-codex" => {
            format!("{model} requires stored OpenAI OAuth; run `kuzushi auth login openai`")
        }
        "anthropic" => {
            format!("{model} requires ANTHROPIC_API_KEY or stored Anthropic OAuth")
        }
        _ => format!("{model} has no compatible configured credential"),
    };
    let metadata = RuntimeFailureMetadata::new(RuntimeFailureClass::Authentication, None, None);
    anyhow::Error::new(RuntimeFailure::new(metadata)).context(guidance)
}

fn run_bridge_with_transport_retries(
    command: &[String],
    request: BridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
    retry_policy: &super::runtime_config::BridgeRetryPolicy,
) -> Result<BridgeResponse> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        ensure_not_cancelled(cancellation)?;
        let (error, failure) =
            match bridge_attempt_outcome(run_bridge(command, &request, cancellation))? {
                BridgeAttempt::Success(response) => return Ok(response),
                BridgeAttempt::Retry { error, failure } => (error, failure),
            };
        if attempt >= transport_retry::max_attempts(&failure, retry_policy) {
            return Err(error);
        }
        transport_retry::sleep_before_retry(
            transport_retry::backoff_delay(attempt, &failure, retry_policy),
            || ensure_not_cancelled(cancellation),
        )?;
    }
}

fn ensure_not_cancelled(cancellation: Option<&kuzushi_core::ScanCancellation>) -> Result<()> {
    if cancellation.is_some_and(kuzushi_core::ScanCancellation::is_cancelled) {
        anyhow::bail!("LangGraph bridge cancelled");
    }
    Ok(())
}

enum BridgeAttempt {
    Success(BridgeResponse),
    Retry {
        error: anyhow::Error,
        failure: transport_retry::TransientFailure,
    },
}

fn bridge_attempt_outcome(result: Result<BridgeResponse>) -> Result<BridgeAttempt> {
    match result {
        Ok(response) if response.ok => Ok(BridgeAttempt::Success(response)),
        Ok(response) => bridge_response_error(response),
        Err(error) => bridge_transport_error(error),
    }
}

fn bridge_response_error(response: BridgeResponse) -> Result<BridgeAttempt> {
    let failure = if response.error_class.as_deref() == Some("mcp_timeout") {
        None
    } else {
        transport_retry::response_transient_failure(
            response.status,
            response.error_class.as_deref(),
            response.error.as_deref(),
            response.retry_after_seconds,
        )
    };
    let error = bridge_runtime_failure(
        response.error_class.as_deref(),
        response.status,
        response.error.as_deref(),
        response.detail.as_deref(),
    );
    let Some(failure) = failure else {
        return Err(error);
    };
    Ok(BridgeAttempt::Retry { error, failure })
}

fn bridge_transport_error(error: anyhow::Error) -> Result<BridgeAttempt> {
    let message = error.to_string();
    let error = bridge_runtime_failure(None, None, Some(&message), None);
    let Some(failure) = transport_retry::message_transient_failure(&message) else {
        return Err(error);
    };
    Ok(BridgeAttempt::Retry { error, failure })
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> Result<TriageOutcome> {
    let response = response.validate_cost()?;
    let call_cost = response.checked_cost_report()?;
    if let Some(structured) = response.structured {
        return structured_triage_outcome(structured, call_cost);
    }
    text_triage_outcome(response, call_cost)
}

fn structured_triage_outcome(
    mut structured: serde_json::Value,
    call_cost: RuntimeCostReport,
) -> Result<TriageOutcome> {
    normalize_triage_confidence(&mut structured);
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured)
        .map_err(|_| anyhow::anyhow!("LangGraph triage JSON violated schema"))?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

fn text_triage_outcome(
    response: AgentQueryResponse,
    call_cost: RuntimeCostReport,
) -> Result<TriageOutcome> {
    if response.truncated {
        let stop_reason = response.stop_reason.as_deref().unwrap_or("length");
        anyhow::bail!(
            "LangGraph triage response was truncated (stopReason: {stop_reason:?}); refusing to synthesize a verdict"
        );
    }
    let text = response.text.trim();
    if text.is_empty() {
        anyhow::bail!("LangGraph bridge returned no triage content");
    }
    let mut value = serde_json::from_str::<serde_json::Value>(strip_whole_json_fence(text))
        .map_err(|_| anyhow::anyhow!("LangGraph triage response was not valid triage JSON"))?;
    normalize_triage_confidence(&mut value);
    let mut outcome = serde_json::from_value::<TriageOutcome>(value)
        .map_err(|_| anyhow::anyhow!("LangGraph triage response violated triage schema"))?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

fn apply_call_cost(outcome: &mut TriageOutcome, call_cost: RuntimeCostReport) {
    outcome.cost_usd = call_cost.observed_usd();
    outcome.cost_usd_exact = call_cost.is_complete();
}

fn strip_whole_json_fence(text: &str) -> &str {
    let Some(without_open) = text.strip_prefix("```") else {
        return text;
    };
    let without_lang = without_open
        .strip_prefix("json")
        .or_else(|| without_open.strip_prefix("JSON"))
        .unwrap_or(without_open)
        .trim_start();
    without_lang
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(text)
}

fn triage_structured_output() -> AgentStructuredOutput {
    AgentStructuredOutput::json_schema(
        "kuzushi_triage_outcome",
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["verdict", "confidence", "rationale"],
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive", "needs_review"]
                },
                "confidence": {
                    "oneOf": [
                        {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        {"type": "string", "enum": ["high", "medium", "low"]}
                    ]
                },
                "rationale": {"type": "string"}
            }
        }),
    )
}
