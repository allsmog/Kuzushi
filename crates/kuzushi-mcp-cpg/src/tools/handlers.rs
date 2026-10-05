//! Handlers for the structural query tools. Each call loads (or implicitly
//! builds) the target's per-language projects on a blocking thread and
//! projects records to JSON.

use crate::engine::{query_languages, target_root, with_language_projects};
use anyhow::Result;
use async_trait::async_trait;
use kuzushi_cpg::queries;
use kuzushi_mcp_common::ToolHandler;
use serde_json::{json, Value};

#[cfg(test)]
mod tests;

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
        "selector": format!("{lang}:{}", record.selector),
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
            let (projects, function) = method_scope(projects, &function)?;
            ensure_unique_function(projects, function)?;
            let callers =
                method_results(projects, |project| queries::callers_of(project, function))?;
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
            let (projects, function) = method_scope(projects, &function)?;
            ensure_unique_function(projects, function)?;
            let mut callees = Vec::new();
            for (lang, project) in projects {
                callees.extend(
                    queries::callees_of(project, function)
                        .map_err(anyhow::Error::msg)?
                        .into_iter()
                        .map(|callee| json!({"callee":callee, "language":lang})),
                );
            }
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
            ensure_unique_file(projects, &file)?;
            let mut definitions = Vec::new();
            for (lang, project) in projects {
                let records = queries::reaching_defs(project, &file, line, &var)
                    .map_err(anyhow::Error::msg)?;
                definitions.extend(records.iter().map(|record| reaching_def_json(record, lang)));
            }
            Ok(
                json!({"var": var, "file": file, "line": line, "definitions": definitions,
                "membershipEvidence": "unambiguous AST node at requested line"}),
            )
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
            ensure_unique_file(projects, &file)?;
            let mut matches = method_results(projects, |project|
                queries::method_at(project, &file, line).map(|record| record.into_iter().collect()))?;
            let method = matches.pop().unwrap_or(Value::Null);
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
        let depth = requested_depth(&args)?;
        with_language_projects(move |_, projects| {
            let (projects, method) = method_scope(projects, &method)?;
            ensure_unique_function(projects, method)?;
            let mut entries = Vec::new();
            let mut truncated = false;
            for (lang, project) in projects {
                let (records, was_truncated) =
                    queries::backward_slice_at(project, method, line, depth)
                        .map_err(anyhow::Error::msg)?;
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

fn method_results(
    projects: &[(String, kuzushi_cpg::Project)],
    query: impl Fn(&kuzushi_cpg::Project) -> queries::QueryResult<Vec<queries::MethodRecord>>,
) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for (lang, project) in projects {
        results.extend(
            query(project)
                .map_err(anyhow::Error::msg)?
                .iter()
                .map(|record| method_json(record, lang)),
        );
    }
    Ok(results)
}

fn method_scope<'a>(
    projects: &'a [(String, kuzushi_cpg::Project)],
    name: &'a str,
) -> Result<(&'a [(String, kuzushi_cpg::Project)], &'a str)> {
    let Some((language, selector)) = name.split_once(":method:") else {
        return Ok((projects, name));
    };
    let index = projects
        .iter()
        .position(|(lang, _)| lang == language)
        .ok_or_else(|| anyhow::anyhow!("method selector names an unavailable language graph"))?;
    let bare = &name[language.len() + 1..];
    anyhow::ensure!(!selector.is_empty(), "method selector is empty");
    Ok((&projects[index..index + 1], bare))
}

fn ensure_unique_function(projects: &[(String, kuzushi_cpg::Project)], name: &str) -> Result<()> {
    let candidates = method_results(projects, |project| {
        Ok(queries::methods_named(project, name))
    })?;
    anyhow::ensure!(
        candidates.len() <= 1,
        "ambiguous method; use a canonical selector from cpg.definitions: {}",
        Value::Array(candidates.into_iter().take(8).collect())
    );
    Ok(())
}

fn ensure_unique_file(projects: &[(String, kuzushi_cpg::Project)], file: &str) -> Result<()> {
    let mut candidates = Vec::new();
    for (lang, project) in projects {
        if let Some(file) = queries::resolved_file(project, file).map_err(anyhow::Error::msg)? {
            candidates.push(json!({"language":lang,"file":file}));
        }
    }
    anyhow::ensure!(
        !candidates.is_empty(),
        "exact file membership unavailable: requested file is absent from loaded language graphs"
    );
    anyhow::ensure!(
        candidates.len() <= 1,
        "ambiguous file across language graphs: {}",
        Value::Array(candidates)
    );
    Ok(())
}

fn reaching_def_json(record: &queries::ReachingDefRecord, lang: &str) -> Value {
    json!({"var":record.var, "defLine":record.def_line, "defCode":record.def_code,
        "useLine":record.use_line, "useCode":record.use_code, "language":lang})
}

fn requested_depth(args: &Value) -> Result<usize> {
    let Some(value) = args.get("depth") else {
        return Ok(2);
    };
    value
        .as_u64()
        .filter(|depth| (0..=32).contains(depth))
        .map(|depth| depth as usize)
        .ok_or_else(|| anyhow::anyhow!("depth must be an integer in 0..=32"))
}
