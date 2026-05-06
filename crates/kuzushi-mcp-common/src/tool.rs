//! Tool registration and dispatch.
//!
//! A backend defines its tools by collecting a [`ToolRegistry`] of
//! [`Tool`] descriptors plus boxed [`ToolHandler`]s, then hands the
//! registry to [`crate::server::serve_stdio`].

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP-facing tool descriptor (serialised in `tools/list` responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    /// JSON Schema describing accepted arguments.
    pub input_schema: Value,
}

/// Trait every tool implementation satisfies. `call` receives the raw
/// `arguments` object from the MCP `tools/call` request and returns a
/// JSON value that becomes the tool result `content`.
#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn call(&self, args: Value) -> Result<Value>;
}

/// In-process registry of tools. Cheap to clone (one Arc per handler).
#[derive(Default)]
pub struct ToolRegistry {
    descriptors: Vec<Tool>,
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(mut self, descriptor: Tool, handler: impl ToolHandler + 'static) -> Self {
        let name = descriptor.name.clone();
        self.descriptors.push(descriptor);
        self.handlers.insert(name, Box::new(handler));
        self
    }

    pub fn descriptors(&self) -> &[Tool] {
        &self.descriptors
    }

    pub async fn call(&self, name: &str, args: Value) -> Result<Value> {
        match self.handlers.get(name) {
            Some(handler) => handler.call(args).await,
            None => anyhow::bail!("unknown tool: {name}"),
        }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct EchoHandler;

    #[async_trait]
    impl ToolHandler for EchoHandler {
        async fn call(&self, args: Value) -> Result<Value> {
            Ok(json!({ "echoed": args }))
        }
    }

    #[tokio::test]
    async fn registry_dispatches_by_name() {
        let registry = ToolRegistry::new().register(
            Tool {
                name: "echo".to_string(),
                description: "Echo arguments back.".to_string(),
                input_schema: json!({ "type": "object" }),
            },
            EchoHandler,
        );

        assert!(registry.contains("echo"));
        let result = registry.call("echo", json!({ "k": 1 })).await.unwrap();
        assert_eq!(result, json!({ "echoed": { "k": 1 } }));
    }

    #[tokio::test]
    async fn unknown_tool_errors_actionably() {
        let registry = ToolRegistry::new();
        let err = registry.call("missing", json!({})).await.unwrap_err();
        assert!(err.to_string().contains("unknown tool"));
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn descriptors_preserve_registration_order() {
        let registry = ToolRegistry::new()
            .register(
                Tool {
                    name: "a".into(),
                    description: "".into(),
                    input_schema: json!({}),
                },
                EchoHandler,
            )
            .register(
                Tool {
                    name: "b".into(),
                    description: "".into(),
                    input_schema: json!({}),
                },
                EchoHandler,
            );
        let names: Vec<_> = registry
            .descriptors()
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
