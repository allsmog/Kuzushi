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
        let source = pattern_argument(&args, "source")?;
        let sink = pattern_argument(&args, "sink")?;
        let max_paths = path_limit(&args)?;
        anyhow::ensure!(
            args.get("maxCallDepth").is_none(),
            "maxCallDepth is unsupported by the summaries-first engine; omit it"
        );
        with_language_projects(move |_, projects| {
            let mut envelope = FlowEnvelope::default();
            for (lang, project) in projects {
                collect_language_flows(&mut envelope, lang, project, &source, &sink, max_paths)?;
            }
            envelope.flows.truncate(max_paths);
            Ok(json!({
                "source": source,
                "sink": sink,
                "maxPaths": max_paths,
                "callDepthPolicy": "engine-unbounded",
                "engine": "cpg-rs",
                "truncated": envelope.truncated,
                "languageCoverage": envelope.coverage,
                "effectivePerLanguageFlowLimit": max_paths.min(kuzushi_cpg::MAX_FLOWS_PER_QUERY),
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
    truncated: bool,
    coverage: Vec<Value>,
}

fn collect_language_flows(
    envelope: &mut FlowEnvelope,
    lang: &str,
    project: &kuzushi_cpg::Project,
    source: &str,
    sink: &str,
    max_paths: usize,
) -> Result<()> {
    if envelope.flows.len() >= max_paths {
        envelope.truncated = true;
        envelope
            .coverage
            .push(json!({"language": lang, "queried": false, "reason": "maxPaths"}));
        return Ok(());
    }
    let harvested =
        kuzushi_cpg::harvest_regex_spec(project, source, sink).map_err(anyhow::Error::msg)?;
    envelope.source_calls += harvested.source_call_matches;
    envelope.entry_methods += harvested.entry_methods.len();
    envelope.sink_calls += harvested.sink_call_matches;
    let (findings, stats) = kuzushi_cpg::run_taint_query(project, &harvested);
    record_query_coverage(envelope, lang, &stats);
    for finding in &findings {
        if envelope.flows.len() >= max_paths {
            envelope.truncated = true;
            break;
        }
        envelope.flows.push(flow_json(lang, finding));
    }
    Ok(())
}

fn record_query_coverage(
    envelope: &mut FlowEnvelope,
    lang: &str,
    stats: &kuzushi_cpg::CpgFlowQueryStats,
) {
    let flow_cap_hit = stats.flow_count_before_cap > stats.flow_count;
    envelope.truncated |= flow_cap_hit || !stats.truncated_categories.is_empty();
    envelope
        .coverage
        .push(json!({"language": lang, "queried": true,
        "flowCandidates": stats.flow_count_before_cap, "flowCapHit": flow_cap_hit,
        "harvestCapsHit": stats.truncated_categories,
        "harvestNameLimit": kuzushi_cpg::MAX_HARVESTED_NAMES,
        "engineFlowLimit": kuzushi_cpg::MAX_FLOWS_PER_QUERY}));
}

fn pattern_argument(args: &Value, key: &'static str) -> Result<String> {
    let mode = args.get("patternMode").map_or(Ok("regex"), |value| {
        value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("patternMode must be a string"))
    })?;
    kuzushi_cpg::compile_query_pattern(&required(args, key)?, mode).map_err(anyhow::Error::msg)
}

fn path_limit(args: &Value) -> Result<usize> {
    match args.get("maxPaths") {
        None => Ok(50),
        Some(value) => value
            .as_u64()
            .filter(|limit| (1..=1000).contains(limit))
            .map(|limit| limit as usize)
            .ok_or_else(|| anyhow::anyhow!("maxPaths must be an integer in 1..=1000")),
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
    async fn invalid_options_fail_before_graph_access() {
        for args in [
            json!({"source":"[","sink":"query"}),
            json!({"source":"req","sink":"query","maxCallDepth":2}),
            json!({"source":"req","sink":"query","maxPaths":4294967296_u64}),
        ] {
            assert!(TaintPathsTool.call(args).await.is_err());
        }
        let literal =
            pattern_argument(&json!({"source":"[", "patternMode":"literal"}), "source").unwrap();
        assert_eq!(literal, "\\[");
    }

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
