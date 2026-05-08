use super::prelude::*;
use super::*;

#[async_trait]
impl ToolHandler for DefinitionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let symbol = require_string(&args, "symbol")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let symbols = run_global_x(&repo, &["-x", "-d", &symbol]).await?;
        Ok(json!({ "symbol": symbol, "matches": symbols }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        symbol_lookup_response(&args, "-r").await
    }
}

#[async_trait]
impl ToolHandler for SymbolsInFileTool {
    async fn call(&self, args: Value) -> Result<Value> {
        symbols_in_file_response(&args).await
    }
}

pub(crate) async fn symbol_lookup_response(args: &Value, flag: &str) -> Result<Value> {
    let request = symbol_lookup_request(args)?;
    run_symbol_lookup(request, flag).await
}

pub(crate) fn symbol_lookup_request(args: &Value) -> Result<GlobalSymbolRequest> {
    let symbol = require_string(args, "symbol")?.to_string();
    ensure_binary_available()?;
    let repo = optional_repo_path(args).unwrap_or_else(|| PathBuf::from("."));
    Ok(GlobalSymbolRequest { repo, symbol })
}

pub(crate) struct GlobalSymbolRequest {
    pub(crate) repo: PathBuf,
    pub(crate) symbol: String,
}

pub(crate) async fn run_symbol_lookup(request: GlobalSymbolRequest, flag: &str) -> Result<Value> {
    let symbols = run_global_x(&request.repo, &["-x", flag, &request.symbol]).await?;
    Ok(json!({ "symbol": request.symbol, "matches": symbols }))
}

pub(crate) async fn symbols_in_file_response(args: &Value) -> Result<Value> {
    let request = symbols_in_file_request(args)?;
    run_symbols_in_file(request).await
}

pub(crate) fn symbols_in_file_request(args: &Value) -> Result<GlobalFileRequest> {
    let file = require_string(args, "file")?.to_string();
    ensure_binary_available()?;
    let repo = optional_repo_path(args).unwrap_or_else(|| PathBuf::from("."));
    Ok(GlobalFileRequest { repo, file })
}

pub(crate) struct GlobalFileRequest {
    pub(crate) repo: PathBuf,
    pub(crate) file: String,
}

pub(crate) async fn run_symbols_in_file(request: GlobalFileRequest) -> Result<Value> {
    let symbols = run_global_x(&request.repo, &["-x", "-f", &request.file]).await?;
    Ok(json!({ "file": request.file, "symbols": symbols }))
}

#[async_trait]
impl ToolHandler for FilesMatchingTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let pattern = require_string(&args, "pattern")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let files =
            run_global_lines(&repo, &["-P", &pattern], "failed to spawn `global -P`").await?;
        Ok(json!({ "pattern": pattern, "files": files }))
    }
}

#[async_trait]
impl ToolHandler for CompletionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let prefix = require_string(&args, "prefix")?.to_string();
        ensure_binary_available()?;
        let repo = optional_repo_path(&args).unwrap_or_else(|| PathBuf::from("."));
        let completions =
            run_global_lines(&repo, &["-c", &prefix], "failed to spawn `global -c`").await?;
        Ok(json!({ "prefix": prefix, "completions": completions }))
    }
}
