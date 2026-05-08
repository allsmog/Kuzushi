use super::prelude::*;
use super::*;

#[async_trait]
impl AgentRuntime for PiAgentCoreRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let structured_output = request.structured_output;
        let bridge_request = BridgeRequest {
            model: request.model,
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt,
            prompt: request.prompt,
            structured_output,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
            thinking_level: self.thinking_level.clone(),
            tool_policy: request.tool_policy,
        };

        let response = run_bridge(&self.command, &bridge_request)?;
        if !response.ok {
            anyhow::bail!(
                "pi-agent-core bridge failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            );
        }

        Ok(AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            ..Default::default()
        })
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_blocking(AgentQueryRequest::new(
            request.model,
            request.cwd,
            TRIAGE_SYSTEM_PROMPT.to_string(),
            prompt,
        ))?;

        if let Some(structured) = response.structured {
            if let Ok(outcome) = serde_json::from_value::<TriageOutcome>(structured.clone()) {
                return Ok(clamp_outcome(outcome));
            }
        }

        if !response.text.is_empty() {
            if let Ok(outcome) = serde_json::from_str::<TriageOutcome>(&response.text) {
                return Ok(clamp_outcome(outcome));
            }
            return Ok(TriageOutcome {
                verdict: TriageVerdict::NeedsReview,
                confidence: 0.25,
                rationale: response.text,
                ..Default::default()
            });
        }

        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.0,
            rationale: "pi-agent-core bridge returned no triage content".to_string(),
            ..Default::default()
        })
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
        let messages = build_messages_for_anthropic(&request.prompt, history);
        let bridge_request = NextStepBridgeRequest {
            envelope_type: "next-step",
            model: request.model.clone(),
            cwd: request.cwd.display().to_string(),
            system_prompt: request.system_prompt.clone(),
            messages,
            tools: request
                .tools
                .iter()
                .map(|t| BridgeTool {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema: t.input_schema.clone(),
                })
                .collect(),
            max_tokens: 4096,
            api_key_env: self.api_key_env.clone(),
            api_key: self.api_key.clone(),
            base_url: self.base_url.clone(),
        };

        let response = run_next_step_bridge(&self.command, &bridge_request)?;
        if !response.ok {
            anyhow::bail!(
                "pi-agent-core next-step bridge failed: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            );
        }
        match response.step.as_deref() {
            Some("tool_call") => {
                let call = response
                    .call
                    .context("next-step: tool_call missing call body")?;
                Ok(AgentLoopStep::ToolCall {
                    call: ToolCall {
                        name: call.name,
                        input: call.input,
                        call_id: call.call_id,
                    },
                })
            }
            Some("final") => Ok(AgentLoopStep::Final {
                text: response.text.unwrap_or_default(),
                structured: response.structured,
                cost_usd: response.cost_usd,
            }),
            other => anyhow::bail!(
                "next-step bridge returned unexpected step: {:?}",
                other.unwrap_or("(missing)")
            ),
        }
    }
}
