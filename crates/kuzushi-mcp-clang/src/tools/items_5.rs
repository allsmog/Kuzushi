use super::prelude::*;
use super::*;

pub(crate) async fn call_hierarchy_response_for_client(
    client: &ClangdClient,
    request: &PositionRequest,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    let items =
        prepare_call_hierarchy(client, &request.file.file, request.line, request.column).await?;
    Ok(json!({ field_name: collect_call_hierarchy_calls(client, method, &items).await? }))
}

pub(crate) async fn collect_call_hierarchy_calls(
    client: &ClangdClient,
    method: &str,
    items: &Value,
) -> Result<Vec<Value>> {
    let mut calls = Vec::new();
    for item in json_array(items) {
        let response = client.request(method, json!({ "item": item })).await?;
        extend_with_json_array(&mut calls, &response);
    }
    Ok(calls)
}

pub(crate) fn json_array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

pub(crate) fn extend_with_json_array(target: &mut Vec<Value>, value: &Value) {
    if let Some(items) = value.as_array() {
        target.extend(items.iter().cloned());
    }
}

#[async_trait]
impl ToolHandler for MacroExpandTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        // clangd renders the macro expansion in the hover markdown
        // when the cursor is on a macro name. We surface the raw
        // hover plus a best-effort extraction of any code fence whose
        // body contains the expansion.
        let hover = client
            .request("textDocument/hover", request.params())
            .await?;
        let expansion = extract_first_code_fence(&hover);
        Ok(json!({ "hover": hover, "expansion": expansion }))
    }
}

#[async_trait]
impl ToolHandler for SemanticTokensTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        let raw = client
            .request("textDocument/semanticTokens/full", request.text_document())
            .await?;
        Ok(json!({ "tokens": raw }))
    }
}

#[async_trait]
impl ToolHandler for DiagnosticsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        // LSP 3.17 pull diagnostics. clangd implements this when
        // launched with `--enable-config` (default in modern builds).
        let raw = client
            .request("textDocument/diagnostic", request.text_document())
            .await?;
        Ok(json!({ "diagnostics": raw }))
    }
}

pub(crate) fn extract_first_code_fence(hover: &Value) -> Option<String> {
    let value = hover
        .get("contents")
        .and_then(|c| c.get("value"))
        .or_else(|| hover.get("contents"))
        .and_then(Value::as_str)?;
    let mut lines = value.lines();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```") {
            let mut body = Vec::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    return Some(body.join("\n"));
                }
                body.push(inner.to_string());
            }
        }
    }
    None
}
