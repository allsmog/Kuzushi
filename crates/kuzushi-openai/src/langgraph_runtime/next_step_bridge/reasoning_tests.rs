use super::*;

#[test]
fn next_step_preserves_runtime_reasoning_selection_on_the_wire() {
    let mut config = kuzushi_core::RuntimeConfig::default();
    config.api_key_env = "OPENAI_API_KEY".to_string();
    let runtime = LangGraphRuntime::from_runtime_config(&config, ".")
        .unwrap()
        .with_thinking_level(Some("high".to_string()));
    let request = AgentToolLoopRequest {
        model: "openai-codex:gpt-5.5".to_string(),
        cwd: ".".into(),
        system_prompt: String::new(),
        prompt: String::new(),
        tools: Vec::new(),
        max_steps: 1,
        runtime_options: None,
        temperature: None,
    };
    let wire = serde_json::to_value(next_step_bridge_request(&runtime, &request, &[])).unwrap();
    assert_eq!(wire["thinkingLevel"], "high");
    assert_eq!(wire["model"], "openai-codex:gpt-5.5");
}
