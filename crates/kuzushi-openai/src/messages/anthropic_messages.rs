use kuzushi_core::LoopHistoryEntry;
use serde_json::Value;

pub(crate) fn build_messages_for_anthropic(
    initial_prompt: &str,
    history: &[LoopHistoryEntry],
) -> Vec<Value> {
    let mut messages = Vec::with_capacity(history.len() + 1);
    messages.push(serde_json::json!({
        "role": "user",
        "content": initial_prompt,
    }));
    for entry in history {
        messages.push(history_entry_message(entry));
    }
    messages
}

fn history_entry_message(entry: &LoopHistoryEntry) -> Value {
    match entry {
        LoopHistoryEntry::AssistantToolCall(call) => serde_json::json!({
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "id": call.call_id,
                "name": call.name,
                "input": call.input,
            }],
        }),
        LoopHistoryEntry::ToolResult(result) => serde_json::json!({
            "role": "user",
            "content": [{
                "type": "tool_result",
                "tool_use_id": result.call_id,
                "content": stringify_tool_output(&result.output),
                "is_error": result.is_error,
            }],
        }),
        LoopHistoryEntry::AssistantText(text) => serde_json::json!({
            "role": "assistant",
            "content": text,
        }),
    }
}

pub(crate) fn stringify_tool_output(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<non-serialisable>".to_string()),
    }
}
