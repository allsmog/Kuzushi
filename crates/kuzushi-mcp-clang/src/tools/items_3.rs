use super::prelude::*;
use super::*;

impl PositionRequest {
    pub(crate) fn from_args(args: &Value) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = require_u32(args, "column")?;
        Ok(Self { file, line, column })
    }

    pub(crate) fn from_args_with_default_column(args: &Value, default_column: u32) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = optional_u32(args, "column").unwrap_or(default_column);
        Ok(Self { file, line, column })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        self.file.client(handle).await
    }

    pub(crate) fn params(&self) -> Value {
        position_arg(&self.file.file, self.line, self.column)
    }
}

pub(crate) fn optional_u32(args: &Value, name: &str) -> Option<u32> {
    args.get(name).and_then(Value::as_u64).map(|n| n as u32)
}

#[async_trait]
impl ToolHandler for CompileCommandsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        compile_commands_response(&args).await
    }
}

pub(crate) async fn compile_commands_response(args: &Value) -> Result<Value> {
    let repo = compile_commands_repo(args)?;
    let db = compile_db::resolve(&repo).await?;
    Ok(serde_json::to_value(db)?)
}

pub(crate) fn compile_commands_repo(args: &Value) -> Result<PathBuf> {
    Ok(PathBuf::from(require_str(args, "repoPath")?))
}

pub(crate) async fn open_document(client: &ClangdClient, file: &std::path::Path) -> Result<()> {
    let uri = format!("file://{}", file.display());
    let text = tokio::fs::read_to_string(file).await.unwrap_or_default();
    client
        .notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": clang_language_id(file),
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
}

pub(crate) fn clang_language_id(file: &std::path::Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("c" | "h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh") => "cpp",
        _ => "cpp",
    }
}

pub(crate) fn position_arg(file: &std::path::Path, line: u32, column: u32) -> Value {
    json!({
        "textDocument": { "uri": format!("file://{}", file.display()) },
        // LSP positions are 0-based.
        "position": { "line": line.saturating_sub(1), "character": column.saturating_sub(1) }
    })
}

#[async_trait]
impl ToolHandler for DefinitionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let raw = client
            .request("textDocument/definition", request.params())
            .await?;
        Ok(json!({ "locations": position_locations(&raw) }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let mut params = request.params();
        params["context"] = json!({ "includeDeclaration": true });
        let raw = client.request("textDocument/references", params).await?;
        Ok(json!({ "locations": range_locations(&raw) }))
    }
}
