#[cfg(test)]
mod tests {
    use super::super::*;
    use std::sync::Mutex;

    /// Mock runtime that walks a scripted sequence of [`AgentLoopStep`] outputs
    /// — used to exercise the driver without a real bridge.
    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
        seen: Mutex<Vec<usize>>, // history length seen by each call
    }

    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Self {
            Self {
                steps: Mutex::new(steps),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for ScriptedRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used in these tests")
        }
        fn supports_tools(&self) -> bool {
            true
        }
        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.seen.lock().unwrap().push(history.len());
            let mut s = self.steps.lock().unwrap();
            if s.is_empty() {
                anyhow::bail!("scripted runtime exhausted")
            }
            Ok(s.remove(0))
        }
    }

    fn req() -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: PathBuf::from("/tmp"),
            system_prompt: "you are a tester".to_string(),
            prompt: "do the thing".to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
            }],
            max_steps: 5,
        }
    }

    #[test]
    fn governance_requires_explicit_model_without_fallback() {
        let error = resolve_explicit_model("triage:run", None, None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("triage:run requires an explicit model"));
        assert!(error.contains("will not choose a fallback model"));
    }

    #[test]
    fn governance_validates_provider_model_syntax() {
        assert!(validate_model_spec("openai:gpt-5.5").is_ok());
        assert!(validate_model_spec("gpt-5.5")
            .unwrap_err()
            .to_string()
            .contains("provider:model"));
        assert!(validate_model_spec("openai:")
            .unwrap_err()
            .to_string()
            .contains("both provider and model id"));
    }

    #[test]
    fn driver_returns_final_in_one_step() {
        let runtime = ScriptedRuntime::new(vec![AgentLoopStep::Final {
            text: "done".to_string(),
            structured: Some(serde_json::json!({"verdict": "tp"})),
            cost_usd: Some(0.01),
        }]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "done");
        assert_eq!(outcome.steps_used, 1);
        assert!(!outcome.truncated);
        assert_eq!(outcome.cost_usd, 0.01);
        assert_eq!(outcome.transcript.len(), 1);
        assert!(matches!(
            outcome.transcript[0],
            LoopHistoryEntry::AssistantText(_)
        ));
    }

    #[test]
    fn driver_threads_tool_call_through_handler() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "path": "src/foo.rs" }),
                    call_id: "call_1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "saw foo".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            assert_eq!(call.name, "read_source");
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::json!({ "contents": "fn main() {}" }),
                is_error: false,
            })
        });
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "saw foo");
        assert_eq!(outcome.steps_used, 2);
        // Transcript: ToolCall, ToolResult, AssistantText.
        assert_eq!(outcome.transcript.len(), 3);
        assert!(matches!(
            outcome.transcript[0],
            LoopHistoryEntry::AssistantToolCall(_)
        ));
        assert!(matches!(
            outcome.transcript[1],
            LoopHistoryEntry::ToolResult(_)
        ));
        // History grew between calls — second runtime call should have seen
        // the tool call + result.
        let seen = runtime.seen.lock().unwrap();
        assert_eq!(seen[0], 0);
        assert_eq!(seen[1], 2);
    }

    #[test]
    fn driver_marks_truncation_at_max_steps() {
        // Five tool calls in a row, max_steps=3 → truncate after 3rd ToolCall.
        let runtime = ScriptedRuntime::new(
            (0..5)
                .map(|i| AgentLoopStep::ToolCall {
                    call: ToolCall {
                        name: "read_source".to_string(),
                        input: serde_json::Value::Null,
                        call_id: format!("call_{i}"),
                    },
                })
                .collect(),
        );
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::Value::Null,
                is_error: false,
            })
        });
        let mut request = req();
        request.max_steps = 3;
        let outcome = run_tool_loop(&runtime, &request, &mut tb).unwrap();
        assert!(outcome.truncated);
        assert_eq!(outcome.steps_used, 3);
    }

    #[test]
    fn unknown_tool_is_returned_as_error_result_not_panic() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "no_such_tool".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "call_x".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "ok");
        // The error result must have been threaded through to the next step.
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult in transcript");
        assert!(result.is_error);
        assert!(
            result.output.to_string().contains("unknown tool"),
            "got {:?}",
            result.output
        );
    }

    #[test]
    fn handler_panic_is_caught_as_error_result() {
        // Defence in depth: a tool that panics shouldn't unwind the loop —
        // catch in the handler closure and return a structured error.
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "buggy".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "c1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("buggy", |_| anyhow::bail!("simulated tool failure"));
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult");
        assert!(result.is_error);
        assert!(result.output.to_string().contains("simulated tool failure"));
    }

    #[test]
    fn legacy_runtime_without_supports_tools_is_rejected() {
        struct LegacyRuntime;
        impl AgentRuntime for LegacyRuntime {
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let mut tb = ToolBox::new();
        let err = run_tool_loop(&LegacyRuntime, &req(), &mut tb)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not support tool-augmented loops"),
            "{err}"
        );
    }
    /// Stub runtime that records the system prompt it received so we can
    /// verify the role preamble is prepended exactly once.
    #[derive(Default)]
    struct RecordingRuntime {
        last_system_prompt: Mutex<Option<String>>,
    }

    impl AgentRuntime for RecordingRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.last_system_prompt.lock().unwrap() = Some(request.system_prompt.clone());
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                structured: None,
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not exercised in this test")
        }
    }

    fn request(system_prompt: &str) -> AgentQueryRequest {
        AgentQueryRequest::new("openai:gpt-4.1", PathBuf::from("."), system_prompt, "hello")
    }

    #[test]
    fn generic_role_does_not_modify_system_prompt() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::Generic, request("base prompt"))
            .unwrap();
        assert_eq!(
            runtime.last_system_prompt.lock().unwrap().as_deref(),
            Some("base prompt")
        );
    }

    #[test]
    fn unsafe_block_role_prepends_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::UnsafeBlockReasoner, request("base"))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        assert!(recorded.starts_with("You are a focused Rust unsafe-block reasoner."));
        assert!(recorded.ends_with("base"));
    }

    #[test]
    fn empty_base_prompt_yields_pure_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::FfiBoundaryReasoner, request(""))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        // No leading newline when base was empty.
        assert!(recorded.starts_with("You are a focused Rust FFI-boundary reasoner."));
        assert!(!recorded.contains("\n\n"));
    }

    #[test]
    fn role_names_are_stable() {
        assert_eq!(SubagentRole::Generic.name(), "generic");
        assert_eq!(SubagentRole::UnsafeBlockReasoner.name(), "unsafe-block");
        assert_eq!(
            SubagentRole::LifetimeAliasingReasoner.name(),
            "lifetime-aliasing"
        );
        assert_eq!(SubagentRole::FfiBoundaryReasoner.name(), "ffi-boundary");
    }
}
