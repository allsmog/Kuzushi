use crate::capabilities::uaf_hunt::adapters::clang_subprocess::{
    rewrite_unsupported_method_error, ClangMcpClient,
};
use crate::capabilities::uaf_hunt::application::repo_tools::{
    failed_tool_result, run_uaf_repo_tool, successful_tool_result,
};
use crate::capabilities::uaf_hunt::domain::UafHuntInput;
use crate::runtime::{ToolCall, ToolCallHandler, ToolResult};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub(super) type SharedClangCallStats = Arc<Mutex<ClangCallStats>>;

#[derive(Debug, Default, Clone)]
pub(super) struct ClangCallStats {
    pub(super) calls: u32,
    pub(super) first_error: Option<String>,
}

pub(super) fn new_clang_call_stats() -> SharedClangCallStats {
    Arc::new(Mutex::new(ClangCallStats::default()))
}

pub(super) fn snapshot_clang_call_stats(stats: &SharedClangCallStats) -> ClangCallStats {
    stats.lock().expect("clang stats lock").clone()
}

/// Build the toolbox that handles each agent tool call. The clang
/// tools forward to the long-lived mcp-clang subprocess; the repo
/// tools are handled inline so we don't need to round-trip to a
/// second MCP server.
pub(super) fn build_uaf_hunt_toolbox<'a>(
    target: &Path,
    options: &UafHuntInput,
    clang: &'a mut ClangMcpClient,
    stats: SharedClangCallStats,
) -> UafHuntHandler<'a> {
    UafHuntHandler {
        target: target.to_path_buf(),
        include_non_production: options.include_non_production,
        clang: clang as *mut ClangMcpClient,
        stats,
        _marker: std::marker::PhantomData,
    }
}

/// A `ToolCallHandler` that owns a raw pointer to the `ClangMcpClient`
/// living on the stack of `run_uaf_hunt_report`. Safety: the client's
/// lifetime strictly outlives the handler; the tool-loop is single-threaded.
pub(super) struct UafHuntHandler<'a> {
    target: PathBuf,
    include_non_production: bool,
    clang: *mut ClangMcpClient,
    stats: SharedClangCallStats,
    _marker: std::marker::PhantomData<&'a mut ClangMcpClient>,
}

unsafe impl<'a> Send for UafHuntHandler<'a> {}

impl<'a> ToolCallHandler for UafHuntHandler<'a> {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        let name = call.name.as_str();
        if let Some(clang_method) = clang_tool_method(name) {
            return self.run_clang_tool(call, clang_method);
        }
        Ok(run_uaf_repo_tool(
            &self.target,
            self.include_non_production,
            call,
        ))
    }
}

impl<'a> UafHuntHandler<'a> {
    fn run_clang_tool(&mut self, call: &ToolCall, clang_method: &str) -> Result<ToolResult> {
        let clang = unsafe { &mut *self.clang };
        self.stats.lock().expect("clang stats lock").calls += 1;
        let arguments = clang_tool_arguments(&self.target, call);
        clang
            .call_tool(clang_method, arguments)
            .map(|value| successful_tool_result(call, value))
            .or_else(|error| Ok(self.clang_tool_error_result(call, clang_method, error)))
    }

    fn clang_tool_error_result(
        &self,
        call: &ToolCall,
        clang_method: &str,
        error: anyhow::Error,
    ) -> ToolResult {
        let formatted = format!("{error:#}");
        self.record_first_clang_error(&formatted);
        rewrite_unsupported_method_error(clang_method, &error).map_or_else(
            || failed_tool_result(call, json!({"error": formatted})),
            |advisory| successful_tool_result(call, advisory.to_tool_result()),
        )
    }

    fn record_first_clang_error(&self, formatted: &str) {
        let mut stats = self.stats.lock().expect("clang stats lock");
        if stats.first_error.is_none() {
            stats.first_error = Some(formatted.to_string());
        }
    }
}

fn clang_tool_arguments(target: &Path, call: &ToolCall) -> Value {
    let mut arguments = call.input.clone();
    if let Some(map) = arguments.as_object_mut() {
        map.entry("repoPath".to_string())
            .or_insert_with(|| Value::String(target.display().to_string()));
    }
    arguments
}

fn clang_tool_method(name: &str) -> Option<&'static str> {
    match name {
        "clang_callers" => Some("clang.callers"),
        "clang_callees" => Some("clang.callees"),
        "clang_references" => Some("clang.references"),
        "clang_definition" => Some("clang.definition"),
        "clang_type_at" => Some("clang.type_at"),
        _ => None,
    }
}
