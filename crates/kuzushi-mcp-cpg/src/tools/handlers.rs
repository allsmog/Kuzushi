//! Handlers for the structural query tools. Each call loads (or implicitly
//! builds) the target's per-language projects on a blocking thread and
//! projects records to JSON.

use crate::engine::{query_languages, target_root, with_language_projects};
use anyhow::Result;
use async_trait::async_trait;
use kuzushi_cpg::queries;
use kuzushi_mcp_common::ToolHandler;
use serde_json::{json, Value};

pub fn health_summary() -> Value {
    let root = target_root();
    let (root_display, langs) = match &root {
        Ok(root) => (root.display().to_string(), query_languages(root)),
        Err(_) => ("unresolved".to_string(), Vec::new()),
    };
    json!({
        "engine": "cpg-rs",
        "ready": root.is_ok(),
        "targetRoot": root_display,
        "graphShapeVersion": kuzushi_cpg::GRAPH_SHAPE_VERSION,
        "persistedLanguages": root.as_ref().map(|r| kuzushi_cpg::artifact_langs(r)).unwrap_or_default(),
        "queryLanguages": langs,
        "supportedLanguages": kuzushi_cpg::supported_languages(),
    })
}

pub struct HealthTool;

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(health_summary())
    }
}

pub struct ParseTool;

#[async_trait]
impl ToolHandler for ParseTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        with_language_projects(|root, projects| {
            let graphs: Vec<Value> = projects
                .iter()
                .map(|(lang, project)| {
                    let stats = queries::graph_stats(project);
                    json!({
                        "language": lang,
                        "cpgPath": kuzushi_cpg::artifact_path(root, lang).display().to_string(),
                        "methods": stats.methods,
                        "calls": stats.calls,
                        "nodes": stats.nodes,
                    })
                })
                .collect();
            Ok(json!({
                "target": root.display().to_string(),
                "graphShapeVersion": kuzushi_cpg::GRAPH_SHAPE_VERSION,
                "graphs": graphs,
            }))
        })
        .await
    }
}

fn required_str(args: &Value, key: &'static str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("missing required argument `{key}`"))
}

fn required_line(args: &Value) -> Result<u32> {
    args.get("line")
        .and_then(Value::as_u64)
        .filter(|line| *line >= 1)
        .and_then(|line| u32::try_from(line).ok())
        .ok_or_else(|| {
            anyhow::anyhow!("missing required argument `line` (integer in 1..=4294967295)")
        })
}

fn method_json(record: &queries::MethodRecord, lang: &str) -> Value {
    json!({
        "name": record.name,
        "fullName": record.full_name,
        "signature": record.signature,
        "file": record.file,
        "line": record.line,
        "language": lang,
    })
}

pub struct CallersOfTool;

#[async_trait]
impl ToolHandler for CallersOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let function = required_str(&args, "fn")?;
        with_language_projects(move |_, projects| {
            let callers: Vec<Value> = projects
                .iter()
                .flat_map(|(lang, project)| {
                    queries::callers_of(project, &function)
                        .iter()
                        .map(|record| method_json(record, lang))
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(json!({"fn": function, "callers": callers}))
        })
        .await
    }
}

pub struct CalleesOfTool;

#[async_trait]
impl ToolHandler for CalleesOfTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let function = required_str(&args, "fn")?;
        with_language_projects(move |_, projects| {
            let callees: Vec<Value> = projects
                .iter()
                .flat_map(|(lang, project)| {
                    queries::callees_of(project, &function)
                        .into_iter()
                        .map(|callee| json!({"callee": callee, "language": lang}))
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(json!({"fn": function, "callees": callees}))
        })
        .await
    }
}

pub struct DefinitionsTool;

#[async_trait]
impl ToolHandler for DefinitionsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let function = required_str(&args, "fn")?;
        with_language_projects(move |_, projects| {
            let matches: Vec<Value> = projects
                .iter()
                .flat_map(|(lang, project)| {
                    queries::methods_named(project, &function)
                        .iter()
                        .map(|record| method_json(record, lang))
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(json!({"fn": function, "matches": matches}))
        })
        .await
    }
}

pub struct ReachingDefTool;

#[async_trait]
impl ToolHandler for ReachingDefTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let file = required_str(&args, "file")?;
        let var = required_str(&args, "var")?;
        let line = required_line(&args)?;
        with_language_projects(move |_, projects| {
            let definitions: Vec<Value> = projects
                .iter()
                .flat_map(|(lang, project)| {
                    queries::reaching_defs(project, &file, line, &var)
                        .iter()
                        .map(|record| {
                            json!({
                                "var": record.var,
                                "defLine": record.def_line,
                                "defCode": record.def_code,
                                "useLine": record.use_line,
                                "useCode": record.use_code,
                                "language": lang,
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            Ok(json!({"var": var, "file": file, "line": line, "definitions": definitions}))
        })
        .await
    }
}

pub struct MethodAtTool;

#[async_trait]
impl ToolHandler for MethodAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let file = required_str(&args, "file")?;
        let line = required_line(&args)?;
        with_language_projects(move |_, projects| {
            let method = projects
                .iter()
                .find_map(|(lang, project)| {
                    queries::method_at(project, &file, line)
                        .map(|record| method_json(&record, lang))
                })
                .unwrap_or(Value::Null);
            Ok(json!({"file": file, "line": line, "method": method,
                "matchQuality": "nearest-preceding", "exactContainment": false,
                "limitation": "Method end lines are unavailable; this result does not establish containment."}))
        })
        .await
    }
}

pub struct CpgSizeTool;

#[async_trait]
impl ToolHandler for CpgSizeTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        with_language_projects(|_, projects| {
            let mut totals = (0usize, 0usize, 0usize);
            let per_language: Vec<Value> = projects
                .iter()
                .map(|(lang, project)| {
                    let stats = queries::graph_stats(project);
                    totals.0 += stats.nodes;
                    totals.1 += stats.methods;
                    totals.2 += stats.calls;
                    json!({
                        "language": lang,
                        "nodes": stats.nodes,
                        "methods": stats.methods,
                        "calls": stats.calls,
                        "summaries": stats.summaries,
                    })
                })
                .collect();
            Ok(json!({
                "nodes": totals.0,
                "methods": totals.1,
                "calls": totals.2,
                "languages": per_language,
            }))
        })
        .await
    }
}

pub struct SliceTool;

#[async_trait]
impl ToolHandler for SliceTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let method = required_str(&args, "method")?;
        let line = required_line(&args)?;
        let depth = args.get("depth").and_then(Value::as_u64).unwrap_or(2) as usize;
        with_language_projects(move |_, projects| {
            let mut entries = Vec::new();
            let mut truncated = false;
            for (lang, project) in projects {
                let (records, was_truncated) =
                    queries::backward_slice_at(project, &method, line, depth);
                truncated |= was_truncated;
                entries.extend(records.iter().map(|record| {
                    json!({
                        "file": record.file,
                        "line": record.line,
                        "code": record.code,
                        "method": record.method,
                        "hops": record.hops,
                        "language": lang,
                    })
                }));
            }
            Ok(json!({
                "method": method,
                "line": line,
                "depth": depth,
                "truncated": truncated,
                "entries": entries,
            }))
        })
        .await
    }
}
