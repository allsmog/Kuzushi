//! `cpg.taint_paths`: the joern-compatible envelope over the engine's
//! regex-harvest + summaries-first taint query.

use crate::engine::with_language_projects;
use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::ToolHandler;
use serde_json::{json, Value};

pub struct TaintPathsTool;

#[async_trait]
impl ToolHandler for TaintPathsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let source = required(&args, "source")?;
        let sink = required(&args, "sink")?;
        let max_paths = args.get("maxPaths").and_then(Value::as_u64).unwrap_or(50) as usize;
        let max_call_depth = args.get("maxCallDepth").and_then(Value::as_u64);
        with_language_projects(move |_, projects| {
            let mut envelope = FlowEnvelope::default();
            for (lang, project) in projects {
                collect_language_flows(&mut envelope, lang, project, &source, &sink, max_paths);
            }
            envelope.flows.truncate(max_paths);
            Ok(json!({
                "source": source,
                "sink": sink,
                "maxPaths": max_paths,
                "maxCallDepth": max_call_depth,
                "engine": "cpg-rs",
                "paths": {
                    "sourceCounts": {
                        "calls": envelope.source_calls,
                        "methodParams": envelope.entry_methods,
                    },
                    "sinkCount": envelope.sink_calls,
                    "flowCount": envelope.flows.len(),
                    "flows": envelope.flows,
                },
            }))
        })
        .await
    }
}

#[derive(Default)]
struct FlowEnvelope {
    source_calls: usize,
    entry_methods: usize,
    sink_calls: usize,
    flows: Vec<Value>,
}

fn collect_language_flows(
    envelope: &mut FlowEnvelope,
    lang: &str,
    project: &kuzushi_cpg::Project,
    source: &str,
    sink: &str,
    max_paths: usize,
) {
    if envelope.flows.len() >= max_paths {
        return;
    }
    let harvested = kuzushi_cpg::harvest_regex_spec(project, source, sink);
    envelope.source_calls += harvested.source_call_matches;
    envelope.entry_methods += harvested.entry_methods.len();
    envelope.sink_calls += harvested.sink_call_matches;
    let (findings, _stats) = kuzushi_cpg::run_taint_query(project, &harvested);
    for finding in &findings {
        if envelope.flows.len() >= max_paths {
            break;
        }
        envelope.flows.push(flow_json(lang, finding));
    }
}

fn flow_json(lang: &str, finding: &kuzushi_cpg::Finding) -> Value {
    let steps: Vec<Value> = finding
        .path
        .iter()
        .map(|step| json!({"code": step.code, "line": step.line, "depth": step.depth}))
        .collect();
    json!({
        "language": lang,
        "method": finding.method,
        "sink": finding.sink,
        "sinkFile": finding.sink_file,
        "sinkLine": finding.sink_line,
        "origin": finding.origin,
        "guard": finding.guard,
        "authz": finding.authz,
        "steps": steps,
    })
}

fn required(args: &Value, key: &'static str) -> Result<String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("missing required argument `{key}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ARTIFACT_ENV;

    #[tokio::test]
    async fn taint_paths_returns_the_joern_compatible_envelope() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("users.ts"),
            "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
        )
        .unwrap();
        let artifact = kuzushi_cpg::artifact_dir(temp.path());
        std::fs::create_dir_all(&artifact).unwrap();
        // SAFETY: test-scoped env for target resolution; no parallel test in
        // this crate reads it with a different value.
        unsafe { std::env::set_var(ARTIFACT_ENV, &artifact) };

        let result = TaintPathsTool
            .call(json!({"source": "req\\.query", "sink": "query"}))
            .await
            .unwrap();

        let paths = &result["paths"];
        assert!(paths["sinkCount"].as_u64().unwrap() > 0, "{result}");
        assert!(paths["flowCount"].as_u64().unwrap() > 0, "{result}");
        let flow = &paths["flows"][0];
        assert_eq!(flow["language"], "typescript");
        assert!(flow["steps"].as_array().unwrap().len() >= 2);
        assert_eq!(result["engine"], "cpg-rs");
    }
}
