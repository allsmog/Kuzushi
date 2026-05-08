use super::prelude::*;
use super::*;

#[allow(dead_code)]
pub(crate) fn stub_descriptor(name: &'static str, desc: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: desc.into(),
        input_schema: json!({"type": "object"}),
    }
}

pub(crate) struct HealthTool;

pub(crate) struct ParseTool;

pub(crate) struct QueryTool;

pub(crate) struct CallersOfTool;

pub(crate) struct CalleesOfTool;

pub(crate) struct CpgSizeTool;

pub(crate) struct ReachingDefTool;

pub(crate) struct TaintPathsTool;

pub(crate) struct UnsafeBlocksTool;

pub(crate) struct FfiBoundariesTool;

pub(crate) struct MethodAtTool;

#[allow(dead_code)]
pub(crate) struct NotYetImplemented(pub(crate) &'static str);

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

pub(crate) fn ensure_joern_available() -> Result<()> {
    if which("joern-parse").is_none() && which("joern").is_none() {
        anyhow::bail!(
            "BackendUnavailable: joern not on PATH. Install via https://docs.joern.io/installation."
        );
    }
    Ok(())
}

pub(crate) fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

#[async_trait]
impl ToolHandler for ParseTool {
    async fn call(&self, args: Value) -> Result<Value> {
        parse_tool_response(args).await
    }
}

pub(crate) async fn parse_tool_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    parse_repo_response(&args).await
}

pub(crate) async fn parse_repo_response(args: &Value) -> Result<Value> {
    let repo = parse_repo_path(args)?;
    parse_repo_handle_value(&repo).await
}

pub(crate) fn parse_repo_path(args: &Value) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(require_str(args, "repoPath")?))
}

pub(crate) async fn parse_repo_handle_value(repo: &std::path::Path) -> Result<Value> {
    let handle = parse_repo(repo).await?;
    Ok(serde_json::to_value(handle)?)
}

#[async_trait]
impl ToolHandler for QueryTool {
    async fn call(&self, args: Value) -> Result<Value> {
        query_tool_response(args).await
    }
}

pub(crate) async fn query_tool_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    query_response(&args).await
}

pub(crate) async fn query_response(args: &Value) -> Result<Value> {
    let scala = require_str(args, "scala")?.to_string();
    let raw = run_query(&scala).await?;
    Ok(json!({ "result": parse_raw_json_or_string(raw) }))
}

#[async_trait]
impl ToolHandler for CallersOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        callers_of_response(args).await
    }
}

pub(crate) async fn callers_of_response(args: Value) -> Result<Value> {
    ensure_joern_available()?;
    function_query_response(&args, queries::callers_of, "callers").await
}
