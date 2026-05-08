use super::prelude::*;
use super::*;

#[async_trait]
impl ToolHandler for TypeAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let raw = client
            .request("textDocument/hover", request.params())
            .await?;
        Ok(json!({ "hover": raw }))
    }
}

#[async_trait]
impl ToolHandler for AstTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args_with_default_column(&args, 1)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        // clangd-specific extension; not part of LSP standard.
        let raw = client.request("textDocument/ast", request.params()).await?;
        Ok(json!({ "ast": raw }))
    }
}

pub(crate) fn position_locations(raw: &Value) -> Vec<Position> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Position::new(PathBuf::from(p), l).with_column(c))
        .collect()
}

pub(crate) fn range_locations(raw: &Value) -> Vec<Range> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Range {
            start: Position::new(PathBuf::from(&p), l).with_column(c),
            end: Position::new(PathBuf::from(p), l).with_column(c),
        })
        .collect()
}

pub(crate) async fn prepare_call_hierarchy(
    client: &ClangdClient,
    file: &std::path::Path,
    line: u32,
    column: u32,
) -> Result<Value> {
    open_document(client, file).await?;
    let raw = client
        .request(
            "textDocument/prepareCallHierarchy",
            position_arg(file, line, column),
        )
        .await?;
    // clangd returns a `CallHierarchyItem[]`; we forward it verbatim.
    Ok(raw)
}

#[async_trait]
impl ToolHandler for CallersTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/incomingCalls",
            "incomingCalls",
        )
        .await
    }
}

#[async_trait]
impl ToolHandler for CalleesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/outgoingCalls",
            "outgoingCalls",
        )
        .await
    }
}

pub(crate) async fn call_hierarchy_response(
    handle: &ClangdHandle,
    args: &Value,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    ensure_clangd()?;
    call_hierarchy_response_for_available_clangd(handle, args, method, field_name).await
}

pub(crate) async fn call_hierarchy_response_for_available_clangd(
    handle: &ClangdHandle,
    args: &Value,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    let request = PositionRequest::from_args(args)?;
    call_hierarchy_response_for_request(handle, request, method, field_name).await
}

pub(crate) async fn call_hierarchy_response_for_request(
    handle: &ClangdHandle,
    request: PositionRequest,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    let client = request.client(handle).await?;
    call_hierarchy_response_for_client(&client, &request, method, field_name).await
}
