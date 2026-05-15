use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_REL_PATH: &str = ".kuzushi/threat-leads.json";
const SUMMARY_REL_PATH: &str = ".kuzushi/threat-leads.md";
const MAX_SCAN_FILES: usize = 6000;
const MAX_FILE_BYTES: u64 = 512 * 1024;
const MAX_CANDIDATE_FILES_PER_THREAT: usize = 12;

#[derive(Debug, Clone)]
struct LeadPattern {
    id: &'static str,
    source: &'static str,
    sink: &'static str,
    source_terms: &'static [&'static str],
    sink_terms: &'static [&'static str],
    trigger_terms: &'static [&'static str],
    cwes: &'static [&'static str],
}

const LEAD_PATTERNS: &[LeadPattern] = &[
    LeadPattern {
        id: "remote-path-to-local-write",
        source: "remote peer controls URL, directory-listing metadata, headers, or response names",
        sink: "local filesystem write/open path",
        source_terms: &[
            "url", "remote", "server", "ftp", "http", "protocol", "filename", "path",
        ],
        sink_terms: &["fopen", "open(", "write", "rename", "unlink", "file"],
        trigger_terms: &[
            "file",
            "path",
            "filename",
            "overwrite",
            "traversal",
            "url",
            "helper",
        ],
        cwes: &["CWE-22", "CWE-73"],
    },
    LeadPattern {
        id: "remote-parser-resource-exhaustion",
        source: "remote peer controls protocol bytes, headers, or response bodies",
        sink: "parser loop, allocation, decompression, or buffering",
        source_terms: &["remote", "server", "protocol", "header", "response", "body"],
        sink_terms: &[
            "parse", "alloc", "malloc", "realloc", "loop", "timeout", "size",
        ],
        trigger_terms: &["parser", "resource", "exhaustion", "hang", "crash", "dos"],
        cwes: &["CWE-400", "CWE-770"],
    },
    LeadPattern {
        id: "credential-or-request-data-leak",
        source: "local credentials, tokens, auth headers, cookies, or request data",
        sink: "remote endpoint, proxy, redirect, log, or diagnostic output",
        source_terms: &["credential", "token", "auth", "cookie", "header", "secret"],
        sink_terms: &["send", "proxy", "redirect", "log", "verbose", "trace"],
        trigger_terms: &[
            "credential",
            "token",
            "leak",
            "disclosure",
            "remote",
            "endpoint",
        ],
        cwes: &["CWE-200", "CWE-201", "CWE-359"],
    },
    LeadPattern {
        id: "ci-build-supply-chain",
        source: "workflow, build script, dependency lookup, or package metadata",
        sink: "CI execution, artifact generation, dependency loading, or release output",
        source_terms: &[
            "workflow",
            "action",
            "dependency",
            "cmake",
            "configure",
            "pkg-config",
        ],
        sink_terms: &["run", "exec", "script", "artifact", "upload", "link"],
        trigger_terms: &[
            "workflow",
            "ci",
            "dependency",
            "build",
            "artifact",
            "supply",
        ],
        cwes: &["CWE-829", "CWE-345"],
    },
];

pub fn execute_threat_leads_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "threat-leads:build" => build_threat_leads_tool(&input, ctx),
        "threat-leads:read" => read_threat_leads_tool(&input, ctx),
        other => anyhow::bail!("unknown threat-leads tool {other:?}"),
    }
}

pub fn build_threat_leads_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(input, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "build",
                format!("threat-leads start · target={}", target.display()),
            )
            .emit();
    }
    let report = build_threat_leads(&target)?;
    write_threat_leads(&target, &report)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "build",
                format!(
                    "threat-leads complete · {} lead{}",
                    report["leadCount"].as_u64().unwrap_or_default(),
                    if report["leadCount"].as_u64() == Some(1) {
                        ""
                    } else {
                        "s"
                    }
                ),
            )
            .emit();
    }
    Ok(tool_output(&target, report))
}

pub fn read_threat_leads_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(input, ctx)?;
    let report = read_threat_leads(&target)?;
    Ok(tool_output(&target, report))
}

pub fn build_threat_leads(target: &Path) -> Result<Value> {
    let threat_model = read_threat_model(target)?;
    let files = collect_scan_files(target)?;
    let file_index = index_files(target, &files);
    let threats = threat_model
        .get("threats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let dfd = threat_model
        .get("dfd")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let nodes = map_by_id(dfd.get("nodes").and_then(Value::as_array));
    let flows = map_by_id(dfd.get("flows").and_then(Value::as_array));
    let mut leads = threats
        .iter()
        .filter_map(|threat| threat_lead(threat, &nodes, &flows, &file_index))
        .collect::<Vec<_>>();
    leads.sort_by(|a, b| {
        lead_priority(b)
            .cmp(&lead_priority(a))
            .then_with(|| threat_id_number(a).cmp(&threat_id_number(b)))
            .then_with(|| a["threatId"].as_str().cmp(&b["threatId"].as_str()))
    });

    Ok(json!({
        "schemaVersion": 1,
        "target": target.display().to_string(),
        "leadCount": leads.len(),
        "leads": leads,
        "sources": {
            "threatModel": ARTIFACT_REL_PATH.replace("threat-leads", "threat-model"),
            "xRay": ["x-ray/entry-points.md", "x-ray/x-ray.md", "x-ray/invariants.md"]
        }
    }))
}

pub fn read_threat_leads(target: &Path) -> Result<Value> {
    let path = target.join(ARTIFACT_REL_PATH);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Could not read threat leads artifact {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("Could not parse threat leads artifact {}", path.display()))
}

fn tool_output(target: &Path, report: Value) -> Value {
    let count = report["leadCount"].as_u64().unwrap_or_default();
    json!({
        "ok": true,
        "output": format!(
            "threat-leads: {} lead{} for {}\n  Artifact: {}",
            count,
            if count == 1 { "" } else { "s" },
            target.display(),
            target.join(ARTIFACT_REL_PATH).display()
        ),
        "data": report,
    })
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            return Ok(if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            });
        }
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

fn read_threat_model(target: &Path) -> Result<Value> {
    let path = target.join(".kuzushi/threat-model.json");
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Could not read threat model {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Could not parse {}", path.display()))
}

fn write_threat_leads(target: &Path, report: &Value) -> Result<()> {
    let path = target.join(ARTIFACT_REL_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(report)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    let summary_path = target.join(SUMMARY_REL_PATH);
    fs::write(&summary_path, render_threat_leads_markdown(report))
        .with_context(|| format!("Could not write {}", summary_path.display()))
}

fn render_threat_leads_markdown(report: &Value) -> String {
    let mut lines = vec![
        "# Threat Leads".to_string(),
        String::new(),
        format!(
            "Generated {} lead cards from threat model, X-Ray, and bounded source evidence.",
            report["leadCount"].as_u64().unwrap_or_default()
        ),
    ];
    let priority_leads = report
        .get("leads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(4)
        .collect::<Vec<_>>();
    if !priority_leads.is_empty() {
        lines.push(String::new());
        lines.push("Priority lead cards:".to_string());
        for lead in priority_leads {
            let threat_id = lead["threatId"].as_str().unwrap_or("unknown");
            let title = lead["title"].as_str().unwrap_or("untitled");
            let pattern = lead["pattern"].as_str().unwrap_or("unknown");
            let candidates = lead["candidateFiles"]
                .as_array()
                .into_iter()
                .flatten()
                .take(3)
                .filter_map(|candidate| candidate["path"].as_str())
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!(
                "- {threat_id}: {title} [{pattern}] candidates: {candidates}"
            ));
        }
    }
    for lead in report
        .get("leads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let threat_id = lead["threatId"].as_str().unwrap_or("unknown");
        let title = lead["title"].as_str().unwrap_or("untitled");
        lines.push(String::new());
        lines.push(format!("## {threat_id}: {title}"));
        push_optional_line(&mut lines, "Pattern", lead["pattern"].as_str());
        push_optional_line(&mut lines, "Source", lead["source"].as_str());
        push_optional_line(&mut lines, "Sink", lead["sink"].as_str());
        push_optional_line(
            &mut lines,
            "Classification",
            lead["classification"].as_str(),
        );
        push_optional_line(&mut lines, "Confidence", lead["confidence"].as_str());
        if let Some(candidates) = lead["candidateFiles"].as_array() {
            lines.push("Top candidate files:".to_string());
            for candidate in candidates.iter().take(5) {
                let path = candidate["path"].as_str().unwrap_or("unknown");
                let classification = candidate["classification"].as_str().unwrap_or("unknown");
                let evidence = candidate["evidence"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(8)
                    .filter_map(|item| item["term"].as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!(
                    "  - `{path}` ({classification}) evidence: {evidence}"
                ));
            }
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

fn push_optional_line(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        lines.push(format!("{label}: {value}"));
    }
}

fn threat_lead(
    threat: &Value,
    nodes: &BTreeMap<String, Value>,
    flows: &BTreeMap<String, Value>,
    file_index: &[IndexedFile],
) -> Option<Value> {
    let id = string_field(threat, "id")?;
    let threat_text = searchable_threat_text(threat);
    let pattern = best_pattern(&threat_text)?;
    let affected_files = string_array_field(threat, "affectedFiles");
    let target_ids = string_array_field(threat, "targetElementIds");
    let linked_nodes = target_ids
        .iter()
        .filter_map(|id| nodes.get(id).map(|node| summarized_node(id, node)))
        .collect::<Vec<_>>();
    let linked_flows = target_ids
        .iter()
        .filter_map(|id| flows.get(id).map(|flow| summarized_flow(id, flow, nodes)))
        .collect::<Vec<_>>();
    let candidates = candidate_files(pattern, &affected_files, file_index);
    let confidence = if candidates.iter().any(|candidate| {
        candidate["evidence"]
            .as_array()
            .is_some_and(|items| items.len() >= 2)
    }) {
        "high"
    } else if candidates.is_empty() {
        "low"
    } else {
        "medium"
    };

    Some(json!({
        "threatId": id,
        "title": string_field(threat, "title").unwrap_or_else(|| id.clone()),
        "category": string_field(threat, "category"),
        "impact": string_field(threat, "impact"),
        "likelihood": string_field(threat, "likelihood"),
        "pattern": pattern.id,
        "source": pattern.source,
        "sink": pattern.sink,
        "candidateFiles": candidates,
        "affectedFiles": affected_files,
        "linkedNodes": linked_nodes,
        "linkedFlows": linked_flows,
        "preconditions": string_field(threat, "preconditions"),
        "missingMitigations": string_field(threat, "missingMitigations"),
        "cwe": pattern.cwes,
        "classification": lead_classification(&candidates),
        "confidence": confidence,
    }))
}

fn searchable_threat_text(threat: &Value) -> String {
    [
        "title",
        "description",
        "impact",
        "attackVector",
        "preconditions",
        "missingMitigations",
        "category",
    ]
    .iter()
    .filter_map(|key| threat.get(*key).and_then(Value::as_str))
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

fn best_pattern(text: &str) -> Option<&'static LeadPattern> {
    LEAD_PATTERNS
        .iter()
        .max_by_key(|pattern| {
            pattern
                .trigger_terms
                .iter()
                .filter(|term| text.contains(**term))
                .count()
        })
        .filter(|pattern| {
            pattern
                .trigger_terms
                .iter()
                .any(|term| text.contains(*term))
        })
}

#[derive(Debug, Clone)]
struct IndexedFile {
    relative: String,
    text: String,
}

fn collect_scan_files(target: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_scan_files_inner(target, target, &mut out)?;
    out.sort();
    out.truncate(MAX_SCAN_FILES);
    Ok(out)
}

fn collect_scan_files_inner(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if should_skip_path(&name) {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_scan_files_inner(root, &path, out)?;
        } else if metadata.is_file()
            && metadata.len() <= MAX_FILE_BYTES
            && is_interesting_source_path(root, &path)
        {
            out.push(path);
        }
        if out.len() >= MAX_SCAN_FILES {
            break;
        }
    }
    Ok(())
}

fn index_files(root: &Path, files: &[PathBuf]) -> Vec<IndexedFile> {
    files
        .iter()
        .filter_map(|path| {
            let text = fs::read_to_string(path).ok()?;
            let relative = path.strip_prefix(root).ok()?.display().to_string();
            Some(IndexedFile {
                relative: relative.replace('\\', "/"),
                text,
            })
        })
        .collect()
}

fn candidate_files(
    pattern: &LeadPattern,
    affected_files: &[String],
    files: &[IndexedFile],
) -> Vec<Value> {
    let mut scored = files
        .iter()
        .filter_map(|file| {
            let affected_bonus = affected_files
                .iter()
                .any(|pattern| path_matches_pattern(&file.relative, pattern));
            let evidence = evidence_terms(file, pattern);
            let score = evidence.len() + usize::from(affected_bonus);
            (score > 0).then(|| {
                (
                    score,
                    json!({
                        "path": file.relative,
                        "classification": classify_path(&file.relative),
                        "evidence": evidence,
                    }),
                )
            })
        })
        .collect::<Vec<_>>();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1["path"].as_str().cmp(&b.1["path"].as_str()))
    });
    scored
        .into_iter()
        .take(MAX_CANDIDATE_FILES_PER_THREAT)
        .map(|(_, value)| value)
        .collect()
}

fn evidence_terms(file: &IndexedFile, pattern: &LeadPattern) -> Vec<Value> {
    let lower = file.text.to_ascii_lowercase();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for term in pattern.source_terms.iter().chain(pattern.sink_terms) {
        if lower.contains(&term.to_ascii_lowercase()) && seen.insert(*term) {
            out.push(json!({"term": term, "kind": evidence_kind(term, pattern)}));
        }
    }
    out
}

fn evidence_kind(term: &str, pattern: &LeadPattern) -> &'static str {
    if pattern.source_terms.contains(&term) {
        "source"
    } else {
        "sink"
    }
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_start_matches("./");
    if pattern.is_empty() {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path.starts_with(prefix.trim_end_matches('/'));
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix.trim_end_matches('/'));
    }
    if pattern.contains('*') {
        let parts = pattern.split('*').collect::<Vec<_>>();
        let mut rest = path;
        for part in parts {
            if part.is_empty() {
                continue;
            }
            let Some(index) = rest.find(part) else {
                return false;
            };
            rest = &rest[index + part.len()..];
        }
        return true;
    }
    path == pattern || path.starts_with(&format!("{pattern}/"))
}

fn map_by_id(values: Option<&Vec<Value>>) -> BTreeMap<String, Value> {
    values
        .into_iter()
        .flatten()
        .filter_map(|value| Some((string_field(value, "id")?, value.clone())))
        .collect()
}

fn summarized_node(id: &str, node: &Value) -> Value {
    json!({
        "id": id,
        "name": string_field(node, "name"),
        "type": string_field(node, "type"),
        "trustZone": string_field(node, "trustZone"),
    })
}

fn summarized_flow(id: &str, flow: &Value, nodes: &BTreeMap<String, Value>) -> Value {
    let source_id = string_field(flow, "sourceId");
    let target_id = string_field(flow, "targetId");
    json!({
        "id": id,
        "description": string_field(flow, "description"),
        "sourceId": source_id,
        "targetId": target_id,
        "source": source_id.as_ref().and_then(|id| nodes.get(id)).and_then(|node| string_field(node, "name")),
        "target": target_id.as_ref().and_then(|id| nodes.get(id)).and_then(|node| string_field(node, "name")),
    })
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn string_array_field(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn lead_classification(candidates: &[Value]) -> &'static str {
    if candidates.iter().all(|candidate| {
        candidate["classification"]
            .as_str()
            .is_some_and(|class| class == "example-code" || class == "test-code")
    }) {
        "example-or-test-only"
    } else {
        "production-or-mixed"
    }
}

fn lead_priority(lead: &Value) -> u8 {
    let mut score = 0;
    if lead["pattern"].as_str() == Some("remote-path-to-local-write") {
        score += 100;
    }
    if lead["classification"].as_str() == Some("production-or-mixed") {
        score += 20;
    }
    if lead["confidence"].as_str() == Some("high") {
        score += 10;
    }
    if lead["title"]
        .as_str()
        .is_some_and(|title| contains_file_write_risk(title))
    {
        score += 10;
    }
    score
}

fn contains_file_write_risk(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["overwrite", "traversal", "file", "path", "helper"]
        .iter()
        .any(|term| lower.contains(term))
}

fn threat_id_number(lead: &Value) -> u32 {
    lead["threatId"]
        .as_str()
        .and_then(|id| id.trim_start_matches('t').parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

fn classify_path(path: &str) -> &'static str {
    if path.starts_with("docs/examples/") || path.contains("/examples/") {
        "example-code"
    } else if path.starts_with("tests/") || path.contains("/tests/") {
        "test-code"
    } else if path.starts_with("docs/") {
        "documentation"
    } else {
        "production-code"
    }
}

fn is_interesting_source_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let relative = relative.display().to_string().replace('\\', "/");
    if relative.starts_with(".kuzushi/") {
        return false;
    }
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "c" | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "rs"
            | "go"
            | "js"
            | "ts"
            | "py"
            | "rb"
            | "php"
            | "java"
            | "sh"
            | "yml"
            | "yaml"
            | "cmake"
            | "txt"
            | "md"
    ) || path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "CMakeLists.txt" | "configure" | "configure.ac" | "Makefile"
            )
        })
}

fn should_skip_path(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".kuzushi"
            | ".next"
            | ".turbo"
            | "coverage"
            | "dist"
            | "native"
            | "node_modules"
            | "target"
            | "build"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_patterns_match_simple_globs() {
        assert!(path_matches_pattern(
            "docs/examples/ftp-wildcard.c",
            "docs/*"
        ));
        assert!(path_matches_pattern(
            ".github/workflows/ci.yml",
            ".github/workflows/*.yml"
        ));
        assert!(!path_matches_pattern("src/tool.c", "docs/*"));
    }

    #[test]
    fn chooses_remote_path_pattern_for_file_overwrite_threat() {
        let pattern = best_pattern(
            "unsafe url-to-file handling in helper paths local file overwrite traversal",
        )
        .expect("pattern");

        assert_eq!(pattern.id, "remote-path-to-local-write");
    }

    #[test]
    fn prioritizes_production_file_write_leads() {
        let low_value = json!({
            "threatId": "t1",
            "title": "Workflow identity spoofing",
            "pattern": "ci-build-supply-chain",
            "classification": "production-or-mixed",
            "confidence": "high",
        });
        let file_write = json!({
            "threatId": "t6",
            "title": "Unsafe URL-to-file handling in helper paths",
            "pattern": "remote-path-to-local-write",
            "classification": "production-or-mixed",
            "confidence": "high",
        });

        assert!(lead_priority(&file_write) > lead_priority(&low_value));
    }
}
