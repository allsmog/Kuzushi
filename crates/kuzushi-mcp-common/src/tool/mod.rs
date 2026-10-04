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
    schemas: HashMap<String, jsonschema::Validator>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(mut self, descriptor: Tool, handler: impl ToolHandler + 'static) -> Self {
        let name = descriptor.name.clone();
        let schema = jsonschema::options()
            .offline()
            .build(&descriptor.input_schema)
            .unwrap_or_else(|error| panic!("invalid MCP schema for {name}: {error}"));
        assert!(
            !self.handlers.contains_key(&name),
            "duplicate MCP tool {name}"
        );
        self.schemas.insert(name.clone(), schema);
        self.descriptors.push(descriptor);
        self.handlers.insert(name, Box::new(handler));
        self
    }

    pub fn descriptors(&self) -> &[Tool] {
        &self.descriptors
    }

    pub async fn call(&self, name: &str, args: Value) -> Result<Value> {
        if let Some(schema) = self.schemas.get(name) {
            anyhow::ensure!(
                schema.is_valid(&args),
                "invalid arguments for {name}: advertised input schema rejected the request"
            );
        }
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

    #[tokio::test]
    async fn invalid_arguments_never_enter_the_handler() {
        struct ForbiddenHandler;
        #[async_trait]
        impl ToolHandler for ForbiddenHandler {
            async fn call(&self, _: Value) -> Result<Value> {
                panic!("invalid request reached handler")
            }
        }
        let registry = ToolRegistry::new().register(Tool { name:"strict".into(), description:String::new(),
            input_schema:json!({"type":"object","required":["line"],"additionalProperties":false,
                "properties":{"line":{"type":"integer","minimum":1,"maximum":99}}}) }, ForbiddenHandler);
        for args in [
            Value::Null,
            json!({}),
            json!({"line":"1"}),
            json!({"line":0}),
            json!({"line":100}),
            json!({"line":1,"unknown":true}),
        ] {
            assert!(registry
                .call("strict", args)
                .await
                .unwrap_err()
                .to_string()
                .contains("invalid arguments"));
        }
    }

    #[test]
    fn schemas_cannot_resolve_files_or_network_resources() {
        assert!(jsonschema::options()
            .offline()
            .build(&json!({"$ref":"file:///etc/passwd"}))
            .is_err());
        assert!(jsonschema::options()
            .offline()
            .build(&json!({"$ref":"https://example.test/schema"}))
            .is_err());
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
