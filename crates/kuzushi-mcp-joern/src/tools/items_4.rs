use super::prelude::*;
use super::*;

pub(crate) async fn method_at_response(args: &Value) -> Result<Value> {
    let request = method_at_request(args)?;
    method_at_query_response(request).await
}

pub(crate) struct MethodAtRequest {
    pub(crate) file: String,
    pub(crate) line: u32,
}

pub(crate) fn method_at_request(args: &Value) -> Result<MethodAtRequest> {
    Ok(MethodAtRequest {
        file: require_str(args, "file")?.to_string(),
        line: method_at_line(args)?,
    })
}

pub(crate) fn method_at_line(args: &Value) -> Result<u32> {
    let line = args
        .get("line")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: line"))?;
    Ok(line as u32)
}

pub(crate) async fn method_at_query_response(request: MethodAtRequest) -> Result<Value> {
    let raw = run_query(&queries::method_at(&request.file, request.line)).await?;
    Ok(method_at_json(request, raw))
}

pub(crate) fn method_at_json(request: MethodAtRequest, raw: String) -> Value {
    let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
    json!({ "file": request.file, "line": request.line, "method": parsed })
}

#[async_trait]
impl ToolHandler for NotYetImplemented {
    async fn call(&self, _args: Value) -> Result<Value> {
        anyhow::bail!(
            "NotYetImplemented: tool `{}` is part of the planned joern MCP surface but is not yet wired.",
            self.0
        )
    }
}
