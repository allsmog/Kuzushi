use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::findings::{Finding, Severity, StaticProofState, TriageVerdict};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::static_evidence::{StaticEvidenceNode, StaticEvidenceStore};

const DEFAULT_VENDOR_PATHS: &[&str] = &[
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "deps",
    "external",
];

const VARIANT_SIGNATURE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Variant Hunter pattern lifter.
Return only JSON matching:
{"source":"where untrusted data enters","sink":"dangerous API or operation","missingGuard":"missing validation or sanitization","languages":["language"],"keywords":["grep keyword"],"description":"portable pattern description"}.
Base the signature on source evidence only."#;

const VARIANT_HUNT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's variant analysis agent.
Return only JSON matching:
{"variants":[{"filePath":"relative/path","startLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","rationale":"source-grounded reason","cwe":["CWE-..."]}]}.
Report only HIGH or MEDIUM confidence variants you verified in source."#;

const NDIFF_FIX_PATTERN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's N-day fix-pattern extractor.
Return only JSON matching:
{"fixShape":"what the patch added","vulnerableShape":"pre-patch vulnerable shape","cwe":["CWE-..."],"languages":["language"],"keywords":["grep keyword"],"detectionQuery":"ripgrep or AST-grep sketch","description":"portable pattern description","confidence":"HIGH|MEDIUM|LOW"}.
Do not invent facts that are not supported by the patch."#;

const NDIFF_HUNT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's N-day variant hunter.
Return only JSON matching:
{"variants":[{"filePath":"relative/path","startLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","rationale":"source-grounded reason","cwe":["CWE-..."]}]}.
Report only code that still has the vulnerable pre-patch shape and lacks the fix shape."#;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CvePatchRef {
    url: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct CveRecord {
    id: String,
    description: String,
    #[serde(default)]
    cwes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f64>,
    #[serde(default)]
    affected: Vec<String>,
    #[serde(default)]
    patches: Vec<CvePatchRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_at: Option<String>,
    source: String,
    #[serde(default)]
    raw: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedRun {
    run_id: String,
    findings_db: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxVariantSearchReport {
    pub count: usize,
    pub patterns: Vec<WhiteboxVariantPattern>,
    pub variants: Vec<Finding>,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxVariantPattern {
    pub original_fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub source_tokens: Vec<String>,
    pub sink_tokens: Vec<String>,
    pub missing_guard_tokens: Vec<String>,
    pub keywords: Vec<String>,
    pub description: String,
}

pub fn hunt_whitebox_static_variants(
    repo_root: impl AsRef<Path>,
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
    max_variants: usize,
) -> Result<WhiteboxVariantSearchReport> {
    let repo_root = repo_root.as_ref();
    let patterns = derive_whitebox_variant_patterns(findings, evidence_store)?;
    let mut variants_by_key = BTreeMap::new();
    if max_variants == 0 {
        return Ok(WhiteboxVariantSearchReport {
            count: 0,
            patterns,
            variants: Vec::new(),
            deterministic: true,
        });
    }

    let source_files = collect_variant_source_files(repo_root)?;
    for pattern in &patterns {
        for source_file in &source_files {
            let Some(relative_path) = repo_relative_path(repo_root, source_file) else {
                continue;
            };
            let text = match fs::read_to_string(source_file) {
                Ok(text) => text,
                Err(_) => continue,
            };
            for (line_index, line) in text.lines().enumerate() {
                let line_no = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
                if relative_path == pattern.file_path && line_no == pattern.start_line {
                    continue;
                }
                let window = line_window(&text, line_index, 2);
                let Some(candidate) = variant_candidate_from_window(
                    repo_root,
                    pattern,
                    &relative_path,
                    line_no,
                    &window,
                    line,
                ) else {
                    continue;
                };
                variants_by_key
                    .entry(candidate.fingerprint.clone())
                    .or_insert(candidate);
                if variants_by_key.len() >= max_variants {
                    break;
                }
            }
            if variants_by_key.len() >= max_variants {
                break;
            }
        }
        if variants_by_key.len() >= max_variants {
            break;
        }
    }

    let variants = variants_by_key.into_values().collect::<Vec<_>>();
    Ok(WhiteboxVariantSearchReport {
        count: variants.len(),
        patterns,
        variants,
        deterministic: true,
    })
}

pub fn derive_whitebox_variant_patterns(
    findings: &[Finding],
    evidence_store: Option<&StaticEvidenceStore>,
) -> Result<Vec<WhiteboxVariantPattern>> {
    let mut patterns = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| finding.static_proof_state == Some(StaticProofState::StaticallyConfirmed))
    {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        if let Some(pattern) = derive_whitebox_variant_pattern(finding, &evidence_nodes) {
            patterns.push(pattern);
        }
    }
    patterns.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.start_line.cmp(&right.start_line))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
            .then_with(|| left.original_fingerprint.cmp(&right.original_fingerprint))
    });
    Ok(patterns)
}

pub fn run_variant_lift_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let fingerprint = match input.get("fingerprint").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "variant:lift-pattern requires a fingerprint.",
            }))
        }
    };
    let workspace = ctx.workspace.context(
        "variant:lift-pattern needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("variant:lift-pattern requires the active workspace findings store")?;
    let Some(finding) = store.get_finding_by_reference(&fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "No finding with fingerprint \"{}\" in {}.",
                fingerprint,
                workspace.findings_db_path().display()
            ),
        }));
    };
    let runtime = require_runtime("variant:lift-pattern", runtime)?;
    let model = require_model("variant:lift-pattern", &input, ctx)?;
    let prompt = build_variant_lift_prompt(&finding);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        workspace.root().to_path_buf(),
        VARIANT_SIGNATURE_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let signature = parse_agent_response("variant:lift-pattern", response)?;
    let object = signature
        .as_object()
        .context("variant:lift-pattern output parse failed: expected a JSON object")?;
    let output = [
        format!(
            "Variant signature for {} ({}:{}):",
            finding.rule_id, finding.file_path, finding.start_line
        ),
        format!(
            "  Source:        {}",
            read_object_string(object, &["source"]).unwrap_or_default()
        ),
        format!(
            "  Sink:          {}",
            read_object_string(object, &["sink"]).unwrap_or_default()
        ),
        format!(
            "  Missing guard: {}",
            read_object_string(object, &["missingGuard", "missing_guard"]).unwrap_or_default()
        ),
        format!(
            "  Languages:     {}",
            read_object_string_array(object, &["languages"]).join(", ")
        ),
        format!(
            "  Keywords:      {}",
            read_object_string_array(object, &["keywords"]).join(", ")
        ),
        String::new(),
        read_object_string(object, &["description"]).unwrap_or_default(),
    ]
    .join("\n");

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "fingerprint": fingerprint,
            "signature": signature,
            "finding": finding,
        },
        "costUsd": 0.0,
    }))
}

pub fn run_variant_hunt(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let fingerprint = match input.get("fingerprint").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "variant:hunt requires a fingerprint.",
            }))
        }
    };
    let target = resolve_tool_target(&input, ctx)?;
    let workspace = ctx.workspace.context(
        "variant:hunt needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("variant:hunt requires the active workspace findings store")?;
    let Some(finding) = store.get_finding_by_reference(&fingerprint)? else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "No finding with fingerprint \"{}\" in {}.",
                fingerprint,
                workspace.findings_db_path().display()
            ),
        }));
    };
    let Some(triage) = finding.triage.as_ref() else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "variant:hunt expects a confirmed TP; finding \"{}\" has no triage verdict. Run triage:run first.",
                fingerprint
            ),
        }));
    };
    if triage.verdict != TriageVerdict::TruePositive {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "variant:hunt expects a confirmed TP; finding \"{}\" has verdict \"{}\".",
                fingerprint,
                triage.verdict.as_str()
            ),
        }));
    }
    let runtime = require_runtime("variant:hunt", runtime)?;
    let model = require_model("variant:hunt", &input, ctx)?;
    let max_findings = positive_usize_input(&input, "maxFindings", 10, 50);
    let include_vendored = input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let vendor_paths = vendor_paths_from_input(&input);
    let prompt = build_variant_hunt_prompt(&finding, include_vendored, &vendor_paths);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        VARIANT_HUNT_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let raw = parse_agent_response("variant:hunt", response)?;
    let repo_name = repo_name(&target);
    let findings = normalize_variant_findings(raw, &target, &repo_name, &finding, max_findings)?;
    let persisted = persist_findings(&target, &findings, ctx)?;
    let output = render_variant_hunt_output(
        &finding,
        findings.len(),
        include_vendored,
        findings.as_slice(),
    );

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "fingerprint": fingerprint,
            "originalFinding": finding,
            "variants": findings,
            "scope": {
                "includeVendored": include_vendored,
                "vendorPaths": if include_vendored { vendor_paths } else { Vec::<String>::new() },
            },
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

pub fn run_ndiff_fetch_cve(input: Value) -> Result<Value> {
    let id = match input.get("id").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => {
            return Ok(json!({
                "ok": false,
                "output": "ndiff:fetch-cve requires an `id`.",
            }))
        }
    };
    match fetch_cve_or_advisory(&id, &input) {
        Ok(Some(record)) => {
            let primary_patch_url = choose_primary_patch_url(&record);
            Ok(json!({
                "ok": true,
                "output": format_cve_summary(&record),
                "data": {
                    "record": record,
                    "primaryPatchUrl": primary_patch_url,
                },
            }))
        }
        Ok(None) => Ok(json!({
            "ok": false,
            "output": format!(
                "No advisory found for \"{}\" (offline={}).",
                id,
                input.get("offline").and_then(Value::as_bool).unwrap_or(false)
            ),
        })),
        Err(error) => Ok(json!({
            "ok": false,
            "output": format!("ndiff:fetch-cve error: {error:#}"),
        })),
    }
}

pub fn run_ndiff_extract_fix_pattern(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let mut record = None;
    let id = input
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let mut patch_text = input
        .get("patchText")
        .or_else(|| input.get("patch_text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut patch_url = input
        .get("patchUrl")
        .or_else(|| input.get("patch_url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if patch_text.trim().is_empty() {
        if id.is_none() && patch_url.trim().is_empty() {
            return Ok(json!({
                "ok": false,
                "output": "ndiff:extract-fix-pattern requires at least one of: id, patchText, or patchUrl.",
            }));
        }
        if let Some(id) = id.as_deref() {
            match fetch_cve_or_advisory(id, &input) {
                Ok(found) => {
                    if let Some(found) = found {
                        if patch_url.trim().is_empty() {
                            patch_url = choose_primary_patch_url(&found).unwrap_or_default();
                        }
                        record = Some(found);
                    }
                }
                Err(error) => {
                    return Ok(json!({
                        "ok": false,
                        "output": format!("Could not fetch {id}: {error:#}"),
                    }))
                }
            }
        }
        if !patch_url.trim().is_empty() {
            match fetch_patch_text(&patch_url, &input) {
                Ok(Some(text)) => patch_text = text,
                Ok(None) => {
                    return Ok(json!({
                        "ok": false,
                        "output": format!(
                            "Could not fetch patch content from {}{}.",
                            patch_url,
                            if input.get("offline").and_then(Value::as_bool).unwrap_or(false) {
                                " (offline mode)"
                            } else {
                                ""
                            }
                        ),
                    }))
                }
                Err(error) => {
                    return Ok(json!({
                        "ok": false,
                        "output": format!("Could not fetch patch content from {patch_url}: {error:#}"),
                    }))
                }
            }
        }
    }

    if patch_text.trim().is_empty() {
        return Ok(json!({
            "ok": false,
            "output": "ndiff:extract-fix-pattern could not resolve any patch content to analyze.",
        }));
    }

    let runtime = require_runtime("ndiff:extract-fix-pattern", runtime)?;
    let model = require_model("ndiff:extract-fix-pattern", &input, ctx)?;
    let target = resolve_tool_target(&input, ctx)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let prompt = build_ndiff_fix_pattern_prompt(record.as_ref(), &patch_text);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target,
        NDIFF_FIX_PATTERN_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let pattern = parse_agent_response("ndiff:extract-fix-pattern", response)?;
    let object = pattern
        .as_object()
        .context("ndiff:extract-fix-pattern output parse failed: expected a JSON object")?;
    let output = [
        format!(
            "Fix shape:         {}",
            read_object_string(object, &["fixShape", "fix_shape"]).unwrap_or_default()
        ),
        format!(
            "Vulnerable shape:  {}",
            read_object_string(object, &["vulnerableShape", "vulnerable_shape"])
                .unwrap_or_default()
        ),
        format!(
            "CWEs:              {}",
            read_object_string_array(object, &["cwe", "cwes"]).join(", ")
        ),
        format!(
            "Languages:         {}",
            read_object_string_array(object, &["languages"]).join(", ")
        ),
        format!(
            "Keywords:          {}",
            read_object_string_array(object, &["keywords"]).join(", ")
        ),
        format!(
            "Detection query:   {}",
            read_object_string(object, &["detectionQuery", "detection_query"]).unwrap_or_default()
        ),
        format!(
            "Confidence:        {}",
            read_object_string(object, &["confidence"]).unwrap_or_default()
        ),
        String::new(),
        read_object_string(object, &["description"]).unwrap_or_default(),
    ]
    .join("\n");

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "advisory": record,
            "pattern": pattern,
            "patchUrl": patch_url,
        },
        "costUsd": 0.0,
    }))
}

pub fn run_ndiff_hunt_variants(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let pattern = match input.get("pattern").and_then(Value::as_object) {
        Some(pattern) => pattern.clone(),
        None => {
            return Ok(json!({
                "ok": false,
                "output": "ndiff:hunt-variants requires a pattern object.",
            }))
        }
    };
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "ndiff:hunt-variants target is not a directory: {}",
            target.display()
        );
    }
    let runtime = require_runtime("ndiff:hunt-variants", runtime)?;
    let model = require_model("ndiff:hunt-variants", &input, ctx)?;
    let max_findings = positive_usize_input(&input, "maxFindings", 15, 100);
    let include_vendored = input
        .get("includeVendored")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let advisory_id = input
        .get("advisoryId")
        .or_else(|| input.get("advisory_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let prompt = build_ndiff_hunt_prompt(&pattern, &advisory_id, include_vendored);
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        NDIFF_HUNT_SYSTEM_PROMPT.to_string(),
        prompt,
    ))?;
    let raw = parse_agent_response("ndiff:hunt-variants", response)?;
    let repo_name = repo_name(&target);
    let findings = normalize_ndiff_findings(raw, &repo_name, &advisory_id, &pattern, max_findings)?;
    let persisted = persist_findings(&target, &findings, ctx)?;
    let output =
        render_ndiff_hunt_output(&advisory_id, findings.len(), include_vendored, &findings);

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "advisoryId": advisory_id,
            "pattern": pattern,
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn build_variant_lift_prompt(finding: &Finding) -> String {
    let finding_json = serde_json::to_string_pretty(finding).unwrap_or_else(|_| "{}".to_string());
    [
        "Extract a portable semantic signature for this confirmed vulnerability.",
        "Identify the attacker-controlled source, dangerous sink, missing guard, affected languages, and grep-friendly keywords.",
        "Use repository source evidence; do not speculate.",
        "",
        "Finding JSON:",
        &finding_json,
    ]
    .join("\n")
}

fn build_variant_hunt_prompt(
    finding: &Finding,
    include_vendored: bool,
    vendor_paths: &[String],
) -> String {
    let triage = finding
        .triage
        .as_ref()
        .map(|triage| {
            format!(
                "Verdict: {}\nConfidence: {:.2}\nRationale: {}",
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale
            )
        })
        .unwrap_or_else(|| "Verdict: none".to_string());
    let vendor_scope = if include_vendored {
        format!(
            "Extend search scope to vendored and third-party code under: {}.",
            vendor_paths
                .iter()
                .map(|path| format!("{path}/"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "Restrict search to first-party source; skip vendored and third-party directories."
            .to_string()
    };
    [
        "A confirmed vulnerability has been found. Search for other locations with the same vulnerability pattern.",
        "",
        "Confirmed vulnerability:",
        &format!(
            "Tool: {}\nRule: {}\nFile: {}:{}\nSeverity: {}\nMessage: {}",
            finding.tool,
            finding.rule_id,
            finding.file_path,
            finding.start_line,
            finding.severity.as_str(),
            finding.message
        ),
        "",
        "Triage assessment:",
        &triage,
        "",
        "Methodology:",
        "1. Read the original vulnerable code and extract source, sink, and missing guard.",
        "2. Search for the same sink and missing guard elsewhere.",
        "3. Skip the original file:line.",
        "4. Return only verified HIGH or MEDIUM confidence variants.",
        &vendor_scope,
    ]
    .join("\n")
}

fn build_ndiff_fix_pattern_prompt(record: Option<&CveRecord>, patch_text: &str) -> String {
    let advisory = record
        .map(|record| {
            format!(
                "ID: {}\nCWEs: {}\n\n{}",
                record.id,
                if record.cwes.is_empty() {
                    "(none listed)".to_string()
                } else {
                    record.cwes.join(", ")
                },
                record.description.trim()
            )
        })
        .unwrap_or_else(|| {
            "(No structured advisory record supplied; infer from the patch.)".to_string()
        });
    let trimmed = if patch_text.len() > 18_000 {
        format!("{}\n... [truncated]", &patch_text[..18_000])
    } else {
        patch_text.to_string()
    };
    [
        "Extract a portable fix-shape signature from this CVE patch.",
        "Describe what the patch added, the vulnerable pre-patch shape, relevant CWEs, languages, keywords, and a detection query.",
        "",
        "Advisory:",
        &advisory,
        "",
        "Patch diff:",
        "```diff",
        &trimmed,
        "```",
    ]
    .join("\n")
}

fn build_ndiff_hunt_prompt(
    pattern: &Map<String, Value>,
    advisory_id: &str,
    include_vendored: bool,
) -> String {
    let scope = if include_vendored {
        "Extend search to vendored code: node_modules/, vendor/, third_party/, deps/, external/."
    } else {
        "Restrict search to first-party source; skip node_modules/, vendor/, third_party/."
    };
    [
        "Hunt for pre-patch variants of a known advisory.",
        "Find code in the target repository that still has the vulnerable shape and lacks the fix shape.",
        "",
        &format!("Advisory: {advisory_id}"),
        "",
        "Fix-shape signature:",
        &format!(
            "Fix shape:        {}",
            read_object_string(pattern, &["fixShape", "fix_shape"]).unwrap_or_default()
        ),
        &format!(
            "Vulnerable shape: {}",
            read_object_string(pattern, &["vulnerableShape", "vulnerable_shape"])
                .unwrap_or_default()
        ),
        &format!(
            "CWEs:             {}",
            read_object_string_array(pattern, &["cwe", "cwes"]).join(", ")
        ),
        &format!(
            "Languages:        {}",
            read_object_string_array(pattern, &["languages"]).join(", ")
        ),
        &format!(
            "Keywords:         {}",
            read_object_string_array(pattern, &["keywords"]).join(", ")
        ),
        &format!(
            "Detection query:  {}",
            read_object_string(pattern, &["detectionQuery", "detection_query"]).unwrap_or_default()
        ),
        &read_object_string(pattern, &["description"]).unwrap_or_default(),
        "",
        "Methodology:",
        "1. Grep with the supplied keywords and detection query.",
        "2. Read each candidate file.",
        "3. Report only if the vulnerable shape is present and the fix shape is absent.",
        "4. Skip LOW confidence candidates.",
        scope,
    ]
    .join("\n")
}

fn normalize_variant_findings(
    raw: Value,
    target: &Path,
    repo_name: &str,
    original: &Finding,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let variants = variants_array(raw);
    let mut deduped: BTreeMap<String, Finding> = BTreeMap::new();
    for item in variants.into_iter() {
        let Value::Object(object) = item else {
            continue;
        };
        let Some(raw_file_path) = read_object_string(&object, &["filePath", "file_path"]) else {
            continue;
        };
        let file_path = normalize_file_path(target, &raw_file_path);
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|line| *line > 0)
            .unwrap_or(1) as u32;
        if file_path == original.file_path && start_line == original.start_line {
            continue;
        }
        let confidence =
            read_object_string(&object, &["confidence"]).unwrap_or_else(|| "MEDIUM".to_string());
        if confidence.eq_ignore_ascii_case("LOW") {
            continue;
        }
        let severity = severity_from_agent(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or(original.severity.as_str()),
        );
        let rule_id = format!("variant/{}", original.rule_id);
        let cwes = read_object_string_array(&object, &["cwe", "cwes"]);
        let message = variant_message(
            read_object_string(&object, &["message"]).as_deref(),
            read_object_string(&object, &["rationale"]).as_deref(),
            &confidence,
            &cwes,
            &format!("Variant of {}", original.rule_id),
        );
        let mut finding = Finding::new_tool(
            "variant-analysis",
            rule_id,
            file_path.clone(),
            start_line,
            None,
            severity,
            message,
        );
        finding.fingerprint = stable_fingerprint(&[
            repo_name,
            "variant-analysis",
            &original.rule_id,
            &file_path,
            &start_line.to_string(),
        ]);
        deduped
            .entry(finding.fingerprint.clone())
            .or_insert(finding);
        if deduped.len() >= max_findings {
            break;
        }
    }
    let mut findings = deduped.into_values().collect::<Vec<_>>();
    findings.sort_by_key(|finding| finding.severity);
    findings.reverse();
    Ok(findings)
}

fn normalize_ndiff_findings(
    raw: Value,
    repo_name: &str,
    advisory_id: &str,
    pattern: &Map<String, Value>,
    max_findings: usize,
) -> Result<Vec<Finding>> {
    let variants = variants_array(raw);
    let mut findings = Vec::new();
    for item in variants.into_iter() {
        let Value::Object(object) = item else {
            continue;
        };
        let Some(file_path) = read_object_string(&object, &["filePath", "file_path"]) else {
            continue;
        };
        let start_line = read_object_u64(&object, &["startLine", "start_line"])
            .filter(|line| *line > 0)
            .unwrap_or(1) as u32;
        let confidence =
            read_object_string(&object, &["confidence"]).unwrap_or_else(|| "MEDIUM".to_string());
        if confidence.eq_ignore_ascii_case("LOW") {
            continue;
        }
        let severity = severity_from_agent(
            read_object_string(&object, &["severity"])
                .as_deref()
                .unwrap_or("WARNING"),
        );
        let cwes = {
            let from_result = read_object_string_array(&object, &["cwe", "cwes"]);
            if from_result.is_empty() {
                read_object_string_array(pattern, &["cwe", "cwes"])
            } else {
                from_result
            }
        };
        let fallback = format!(
            "Possible unpatched variant of {}: {}",
            advisory_id,
            read_object_string(pattern, &["vulnerableShape", "vulnerable_shape"])
                .unwrap_or_default()
        );
        let message = variant_message(
            read_object_string(&object, &["message"]).as_deref(),
            read_object_string(&object, &["rationale"]).as_deref(),
            &confidence,
            &cwes,
            &fallback,
        );
        let mut finding = Finding::new_tool(
            "n-day-diff-hunter",
            format!("n-day/{advisory_id}"),
            file_path.clone(),
            start_line,
            None,
            severity,
            message,
        );
        finding.fingerprint = format!("{repo_name}:ndiff/{advisory_id}/{file_path}:{start_line}");
        findings.push(finding);
        if findings.len() >= max_findings {
            break;
        }
    }
    Ok(findings)
}

fn derive_whitebox_variant_pattern(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
) -> Option<WhiteboxVariantPattern> {
    let corpus = variant_pattern_corpus(finding, evidence_nodes);
    let source_tokens = matching_tokens(&corpus, WHITEBOX_SOURCE_TOKENS);
    let sink_tokens = matching_tokens(&corpus, WHITEBOX_SINK_TOKENS);
    if source_tokens.is_empty() || sink_tokens.is_empty() {
        return None;
    }

    let mut keywords = BTreeSet::new();
    keywords.extend(source_tokens.iter().cloned());
    keywords.extend(sink_tokens.iter().cloned());
    for token in finding
        .rule_id
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|token| token.len() >= 4)
        .take(4)
    {
        keywords.insert(token.to_ascii_lowercase());
    }

    Some(WhiteboxVariantPattern {
        original_fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        source_tokens: source_tokens.clone(),
        sink_tokens: sink_tokens.clone(),
        missing_guard_tokens: WHITEBOX_GUARD_TOKENS
            .iter()
            .map(|token| (*token).to_string())
            .collect(),
        keywords: keywords.into_iter().collect(),
        description: format!(
            "Find sibling code where {} reaches {} without an obvious sanitizer or guard.",
            source_tokens.join(" or "),
            sink_tokens.join(" or ")
        ),
    })
}

fn variant_candidate_from_window(
    repo_root: &Path,
    pattern: &WhiteboxVariantPattern,
    relative_path: &str,
    line_no: u32,
    window: &str,
    line: &str,
) -> Option<Finding> {
    let lower = window.to_ascii_lowercase();
    let matched_sources = tokens_present(&lower, &pattern.source_tokens);
    let matched_sinks = tokens_present(&lower, &pattern.sink_tokens);
    if matched_sources.is_empty() || matched_sinks.is_empty() {
        return None;
    }
    let line_lower = line.to_ascii_lowercase();
    if tokens_present(&line_lower, &pattern.sink_tokens).is_empty() {
        return None;
    }
    let matched_guards = tokens_present(&lower, &pattern.missing_guard_tokens);
    if !matched_guards.is_empty() {
        return None;
    }

    let repo = repo_name(repo_root);
    let mut finding = Finding::new_tool(
        "whitebox-variant-search",
        format!("whitebox-variant/{}", pattern.rule_id),
        relative_path.to_string(),
        line_no,
        Some(line_no),
        Severity::Medium,
        format!(
            "Static variant candidate of {}. Matched source token(s) {} and sink token(s) {} without obvious guard token(s). Proof starts as code_cited and requires independent validation.\nEvidence: {}",
            pattern.rule_id,
            matched_sources.join(", "),
            matched_sinks.join(", "),
            line.trim()
        ),
    )
    .with_static_proof_state(StaticProofState::CodeCited);
    finding.fingerprint = stable_fingerprint(&[
        &repo,
        "whitebox-variant-search",
        &pattern.original_fingerprint,
        relative_path,
        &line_no.to_string(),
    ]);
    Some(finding)
}

fn variant_pattern_corpus(finding: &Finding, evidence_nodes: &[StaticEvidenceNode]) -> String {
    let mut parts = vec![
        finding.rule_id.as_str(),
        finding.title.as_str(),
        finding.message.as_str(),
        finding.file_path.as_str(),
    ];
    let metadata = evidence_nodes
        .iter()
        .map(|node| node.metadata.to_string())
        .collect::<Vec<_>>();
    for node in evidence_nodes {
        parts.push(node.title.as_str());
        parts.push(node.body.as_str());
        if let Some(source_path) = node.source_path.as_deref() {
            parts.push(source_path);
        }
    }
    for item in &metadata {
        parts.push(item.as_str());
    }
    parts.join("\n").to_ascii_lowercase()
}

fn matching_tokens(corpus: &str, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn tokens_present(corpus: &str, tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .cloned()
        .collect()
}

fn collect_variant_source_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_variant_source_files_inner(repo_root, repo_root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_variant_source_files_inner(
    repo_root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if file_type.is_dir() {
            if ignored_variant_dir(&name) {
                continue;
            }
            collect_variant_source_files_inner(repo_root, &path, files)?;
            continue;
        }
        if file_type.is_file()
            && is_variant_source_file(&path)
            && repo_relative_path(repo_root, &path).is_some()
        {
            files.push(path);
        }
    }
    Ok(())
}

fn repo_relative_path(repo_root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(repo_root).ok().map(|relative| {
        relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/")
    })
}

fn is_variant_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some(
            "js" | "jsx"
                | "ts"
                | "tsx"
                | "mjs"
                | "cjs"
                | "py"
                | "go"
                | "rs"
                | "java"
                | "kt"
                | "rb"
                | "php"
                | "c"
                | "cc"
                | "cpp"
                | "h"
                | "hpp"
        )
    )
}

fn ignored_variant_dir(name: &str) -> bool {
    name.starts_with('.')
        || DEFAULT_VENDOR_PATHS
            .iter()
            .any(|ignored| ignored.eq_ignore_ascii_case(name))
        || matches!(
            name,
            "target" | "dist" | "build" | "coverage" | "__pycache__"
        )
}

fn line_window(text: &str, center_line_index: usize, radius: usize) -> String {
    let lines = text.lines().collect::<Vec<_>>();
    let start = center_line_index.saturating_sub(radius);
    let end = (center_line_index + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn variants_array(raw: Value) -> Vec<Value> {
    match raw {
        Value::Object(mut object) => object
            .remove("variants")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default(),
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

fn variant_message(
    message: Option<&str>,
    rationale: Option<&str>,
    confidence: &str,
    cwes: &[String],
    fallback: &str,
) -> String {
    let mut output = message
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string();
    if let Some(rationale) = rationale.map(str::trim).filter(|value| !value.is_empty()) {
        output.push_str("\nRationale: ");
        output.push_str(rationale);
    }
    output.push_str("\nConfidence: ");
    output.push_str(confidence.trim());
    if !cwes.is_empty() {
        output.push_str("\nCWE: ");
        output.push_str(&cwes.join(", "));
    }
    output
}

fn render_variant_hunt_output(
    original: &Finding,
    count: usize,
    include_vendored: bool,
    findings: &[Finding],
) -> String {
    let mut lines = vec![
        format!(
            "variant:hunt complete for {} ({}:{})",
            original.rule_id, original.file_path, original.start_line
        ),
        format!("  Variants found: {count}"),
        format!(
            "  Scope:          {}",
            if include_vendored {
                "repo + vendored"
            } else {
                "repo only"
            }
        ),
        "  Cost:           $0.0000".to_string(),
    ];
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top variants:".to_string());
        for finding in findings.iter().take(5) {
            lines.push(format!(
                "  - {}:{} ({}) - {}",
                finding.file_path,
                finding.start_line,
                finding.severity.as_str(),
                finding.title
            ));
        }
    }
    lines.join("\n")
}

fn render_ndiff_hunt_output(
    advisory_id: &str,
    count: usize,
    include_vendored: bool,
    findings: &[Finding],
) -> String {
    let mut lines = vec![
        format!("ndiff:hunt-variants complete ({advisory_id})"),
        format!("  Variants:   {count}"),
        format!(
            "  Scope:      {}",
            if include_vendored {
                "repo + vendored"
            } else {
                "repo only"
            }
        ),
        "  Cost:       $0.0000".to_string(),
    ];
    if !findings.is_empty() {
        lines.push(String::new());
        lines.push("Top candidates:".to_string());
        for finding in findings.iter().take(5) {
            lines.push(format!(
                "  - {}:{} ({}) - {}",
                finding.file_path,
                finding.start_line,
                finding.severity.as_str(),
                finding.title
            ));
        }
    }
    lines.join("\n")
}

fn persist_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<PersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };
    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;
    Ok(Some(PersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
    }))
}

fn fetch_cve_or_advisory(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    if let Some(record) = record_from_input(id, input)? {
        return Ok(Some(record));
    }
    if input
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }

    if id.to_ascii_uppercase().starts_with("CVE-") {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
            shell_escape_url(id)
        );
        let raw = curl_json(&url, input, "ndiff:fetch-cve")?;
        return Ok(map_nvd_record(id, raw));
    }
    if id.to_ascii_lowercase().starts_with("ghsa-") {
        let url = format!(
            "https://api.github.com/advisories/{}",
            shell_escape_url(&id.to_ascii_lowercase())
        );
        let raw = curl_json(&url, input, "ndiff:fetch-cve")?;
        return Ok(Some(map_ghsa_record(&id.to_ascii_lowercase(), raw)));
    }
    anyhow::bail!("Unrecognized advisory ID: {id:?} (expected CVE-* or GHSA-*)")
}

fn record_from_input(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    if let Some(Value::Object(record)) = input.get("record") {
        return Ok(Some(serde_json::from_value(Value::Object(record.clone()))?));
    }
    let Some(fixtures) = input.get("fixtures").and_then(Value::as_object) else {
        return Ok(None);
    };
    let candidates = [
        id.to_string(),
        id.to_ascii_uppercase(),
        id.to_ascii_lowercase(),
    ];
    for key in candidates {
        if let Some(value) = fixtures.get(&key) {
            return Ok(Some(serde_json::from_value(value.clone()).with_context(
                || format!("Could not parse offline advisory fixture {key}"),
            )?));
        }
    }
    Ok(None)
}

fn map_nvd_record(id: &str, raw: Value) -> Option<CveRecord> {
    let vulnerabilities = raw.get("vulnerabilities")?.as_array()?;
    let first = vulnerabilities.first()?.clone();
    let cve = first.get("cve").cloned().unwrap_or_else(|| json!({}));
    let description = cve
        .get("descriptions")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                (item.get("lang").and_then(Value::as_str) == Some("en"))
                    .then(|| item.get("value").and_then(Value::as_str))
                    .flatten()
            })
        })
        .unwrap_or_default()
        .to_string();
    let mut cwes = Vec::new();
    if let Some(weaknesses) = cve.get("weaknesses").and_then(Value::as_array) {
        for weakness in weaknesses {
            if let Some(descriptions) = weakness.get("description").and_then(Value::as_array) {
                for description in descriptions {
                    if let Some(value) = description.get("value").and_then(Value::as_str) {
                        if value.starts_with("CWE-") {
                            cwes.push(value.to_string());
                        }
                    }
                }
            }
        }
    }
    let mut patches = Vec::new();
    if let Some(references) = cve.get("references").and_then(Value::as_array) {
        for reference in references {
            let Some(url) = reference.get("url").and_then(Value::as_str) else {
                continue;
            };
            let tags = reference
                .get("tags")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if tags.iter().any(|tag| tag == "Patch")
                || url.contains("/commit/")
                || url.contains("/pull/")
                || url.ends_with(".diff")
                || url.ends_with(".patch")
            {
                patches.push(CvePatchRef {
                    url: url.to_string(),
                    kind: "nvd".to_string(),
                    title: (!tags.is_empty()).then(|| tags.join(",")),
                });
            }
        }
    }
    Some(CveRecord {
        id: id.to_ascii_uppercase(),
        description,
        cwes,
        severity: nvd_severity(&cve),
        cvss_score: nvd_cvss_score(&cve),
        affected: Vec::new(),
        patches,
        published_at: cve
            .get("published")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source: "nvd".to_string(),
        raw: first,
    })
}

fn nvd_severity(cve: &Value) -> Option<String> {
    cve.pointer("/metrics/cvssMetricV31/0/baseSeverity")
        .or_else(|| cve.pointer("/metrics/cvssMetricV31/0/cvssData/baseSeverity"))
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase)
}

fn nvd_cvss_score(cve: &Value) -> Option<f64> {
    cve.pointer("/metrics/cvssMetricV31/0/cvssData/baseScore")
        .and_then(Value::as_f64)
}

fn map_ghsa_record(id: &str, raw: Value) -> CveRecord {
    let cwes = raw
        .get("cwes")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("cwe_id").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let patches = raw
        .get("references")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|url| {
                    url.contains("/commit/")
                        || url.contains("/pull/")
                        || url.ends_with(".diff")
                        || url.ends_with(".patch")
                })
                .map(|url| CvePatchRef {
                    url: url.to_string(),
                    kind: "ghsa".to_string(),
                    title: None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    CveRecord {
        id: raw
            .get("cve_id")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string(),
        description: raw
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        cwes,
        severity: raw
            .get("severity")
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase),
        cvss_score: raw.pointer("/cvss/score").and_then(Value::as_f64),
        affected: Vec::new(),
        patches,
        published_at: raw
            .get("published_at")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        source: "ghsa".to_string(),
        raw,
    }
}

fn choose_primary_patch_url(record: &CveRecord) -> Option<String> {
    fn rank(url: &str) -> usize {
        if url.ends_with(".diff") {
            0
        } else if url.ends_with(".patch") {
            1
        } else if url.contains("/commit/") {
            2
        } else if url.contains("/pull/") {
            3
        } else {
            4
        }
    }
    record
        .patches
        .iter()
        .min_by_key(|patch| rank(&patch.url))
        .map(|patch| patch.url.clone())
}

fn fetch_patch_text(url: &str, input: &Value) -> Result<Option<String>> {
    if let Some(fixtures) = input
        .get("patchFixtures")
        .or_else(|| input.get("patch_fixtures"))
        .and_then(Value::as_object)
    {
        if let Some(text) = fixtures.get(url).and_then(Value::as_str) {
            return Ok(Some(text.to_string()));
        }
    }
    if input
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let path = PathBuf::from(url);
    if path.exists() {
        return fs::read_to_string(&path)
            .map(Some)
            .with_context(|| format!("Could not read patch file {}", path.display()));
    }
    let mut fetch_url = url.to_string();
    let github_commit = url.starts_with("https://github.com/")
        && (url.contains("/commit/") || url.contains("/pull/"))
        && !url.ends_with(".patch")
        && !url.ends_with(".diff");
    if github_commit {
        fetch_url.push_str(".patch");
    }
    curl_text(&fetch_url, input, "ndiff:extract-fix-pattern")
}

fn curl_json(url: &str, input: &Value, tool: &str) -> Result<Value> {
    let text = curl_text(url, input, tool)?.context("curl returned no response body")?;
    serde_json::from_str(&text).with_context(|| format!("{tool} could not parse JSON from {url}"))
}

fn curl_text(url: &str, input: &Value, tool: &str) -> Result<Option<String>> {
    let binary = input
        .get("curlBinary")
        .or_else(|| input.get("curl_binary"))
        .or_else(|| input.get("binary"))
        .and_then(Value::as_str)
        .unwrap_or("curl");
    let mut command = Command::new(binary);
    command
        .args(["-fsSL", "--max-time", "15", "-H", "Accept: text/plain"])
        .arg(url);
    let output = command.output().with_context(|| {
        format!("{tool} requires curl to fetch advisories or patches; install curl or pass patchText/offline fixtures")
    })?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).to_string()))
}

fn format_cve_summary(record: &CveRecord) -> String {
    let mut lines = vec![format!(
        "{} ({})",
        record.id,
        record.source.to_ascii_uppercase()
    )];
    if let Some(severity) = &record.severity {
        lines.push(match record.cvss_score {
            Some(score) => format!("  Severity: {severity} ({score})"),
            None => format!("  Severity: {severity}"),
        });
    }
    if !record.cwes.is_empty() {
        lines.push(format!("  CWEs:     {}", record.cwes.join(", ")));
    }
    if let Some(published_at) = &record.published_at {
        lines.push(format!("  Published: {published_at}"));
    }
    lines.push(String::new());
    lines.push(record.description.trim().to_string());
    if !record.patches.is_empty() {
        lines.push(String::new());
        lines.push("Patches:".to_string());
        for patch in record.patches.iter().take(5) {
            lines.push(format!("  - {}", patch.url));
        }
    }
    lines
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn require_runtime<'a>(
    tool: &str,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<&'a dyn AgentRuntime> {
    runtime.with_context(|| {
        format!("{tool} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.")
    })
}

fn require_model(tool: &str, input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    input
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| ctx.config.model.clone())
        .with_context(|| {
            format!("{tool} requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model")
        })
}

fn parse_agent_response(tool: &str, response: AgentQueryResponse) -> Result<Value> {
    if let Some(structured) = response.structured {
        return Ok(structured);
    }
    if let Ok(value) = serde_json::from_str::<Value>(&response.text) {
        return Ok(value);
    }
    let start = response
        .text
        .find('{')
        .with_context(|| format!("{tool} output parse failed: missing JSON object start"))?;
    let end = response
        .text
        .rfind('}')
        .with_context(|| format!("{tool} output parse failed: missing JSON object end"))?;
    serde_json::from_str(&response.text[start..=end])
        .with_context(|| format!("{tool} output parse failed: invalid JSON object"))
}

fn resolve_tool_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        let path = if trimmed.is_empty() {
            std::env::current_dir().context("Could not resolve current directory")?
        } else {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_absolute() {
                candidate
            } else {
                std::env::current_dir()
                    .context("Could not resolve current directory")?
                    .join(candidate)
            }
        };
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

fn positive_usize_input(input: &Value, key: &str, default: usize, max: usize) -> usize {
    input
        .get(key)
        .and_then(|value| match value {
            Value::Number(number) => number.as_u64().map(|value| value as usize),
            Value::String(text) => text.parse::<usize>().ok(),
            _ => None,
        })
        .filter(|value| *value > 0)
        .unwrap_or(default)
        .min(max)
}

fn vendor_paths_from_input(input: &Value) -> Vec<String> {
    input
        .get("vendorPaths")
        .or_else(|| input.get("vendor_paths"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_VENDOR_PATHS
                .iter()
                .map(|path| (*path).to_string())
                .collect()
        })
}

fn normalize_file_path(root: &Path, file_path: &str) -> String {
    let candidate = PathBuf::from(file_path.trim());
    if candidate.is_absolute() {
        return candidate
            .strip_prefix(root)
            .unwrap_or(&candidate)
            .display()
            .to_string();
    }
    file_path.trim().to_string()
}

fn severity_from_agent(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn read_object_value<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

fn read_object_string_array(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    read_object_value(object, keys)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn stable_fingerprint(parts: &[&str]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in parts {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

fn repo_name(target: &Path) -> String {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo")
        .to_string()
}

fn shell_escape_url(value: &str) -> String {
    value.trim().replace(' ', "%20")
}

const WHITEBOX_SOURCE_TOKENS: &[&str] = &[
    "req.query",
    "req.body",
    "req.params",
    "req.headers",
    "request.args",
    "request.form",
    "request.json",
    "process.argv",
    "argv",
    "urlsearchparams",
    "input",
];

const WHITEBOX_SINK_TOKENS: &[&str] = &[
    "db.query",
    ".query(",
    "execute(",
    "exec(",
    "spawn(",
    "eval(",
    "res.send",
    "innerhtml",
    "deserialize",
    "render(",
];

const WHITEBOX_GUARD_TOKENS: &[&str] = &[
    "sanitize",
    "sanitise",
    "escape",
    "validate",
    "validator",
    "allowlist",
    "allow_list",
    "parameterized",
    "parametrize",
    "prepare(",
    "preparedstatement",
    "dompurify",
    "zod",
    "joi",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::findings::{FindingStore, TriageOutcome};
    use crate::modules::ModuleRegistry;
    use crate::runtime::TriageRequest;
    use crate::workspace::WorkspaceTarget;
    use std::sync::Mutex;
    use tempfile::tempdir;

    struct MockRuntime {
        queries: Mutex<Vec<AgentQueryRequest>>,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                queries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for MockRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let system = request.system_prompt.clone();
            self.queries.lock().unwrap().push(request);
            if system.contains("pattern lifter") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "source": "HTTP request body",
                        "sink": "child_process.exec",
                        "missingGuard": "no allowlist",
                        "languages": ["typescript"],
                        "keywords": ["exec", "child_process"],
                        "description": "Untrusted input reaches shell execution."
                    })),
                    ..Default::default()
                });
            }
            if system.contains("variant analysis") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "variants": [{
                            "filePath": "src/other.ts",
                            "startLine": 9,
                            "severity": "ERROR",
                            "message": "exec with untrusted input",
                            "confidence": "HIGH",
                            "rationale": "same source reaches exec",
                            "cwe": ["CWE-78"]
                        }, {
                            "filePath": "src/weak.ts",
                            "startLine": 12,
                            "severity": "WARNING",
                            "message": "low confidence",
                            "confidence": "LOW",
                            "rationale": "unclear"
                        }]
                    })),
                    ..Default::default()
                });
            }
            if system.contains("fix-pattern extractor") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "fixShape": "adds a bounds check before memcpy",
                        "vulnerableShape": "memcpy uses attacker-controlled length without a bounds check",
                        "cwe": ["CWE-787"],
                        "languages": ["c"],
                        "keywords": ["memcpy", "len"],
                        "detectionQuery": "rg 'memcpy\\('",
                        "description": "Search copies guarded by no length cap.",
                        "confidence": "HIGH"
                    })),
                    ..Default::default()
                });
            }
            if system.contains("N-day variant hunter") {
                return Ok(AgentQueryResponse {
                    text: String::new(),
                    structured: Some(json!({
                        "variants": [{
                            "filePath": "src/parser.c",
                            "startLine": 7,
                            "severity": "ERROR",
                            "message": "memcpy without bounds check",
                            "confidence": "HIGH",
                            "rationale": "length reaches memcpy",
                            "cwe": ["CWE-787"]
                        }]
                    })),
                    ..Default::default()
                });
            }
            anyhow::bail!("unexpected query")
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            anyhow::bail!("triage not used")
        }
    }

    fn seeded_workspace() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, String) {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let run_id = "run-variant";
        store
            .insert_scan_run(run_id, workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.command-injection",
            "src/app.ts",
            1,
            None,
            Severity::High,
            "Command injection via child_process.exec",
        );
        let fingerprint = finding.fingerprint.clone();
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.91,
                    rationale: "user input reaches exec".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        store.complete_scan_run(run_id, "completed", 1).unwrap();
        (temp, workspace, store, fingerprint)
    }

    #[test]
    fn whitebox_variants_derive_pattern_from_confirmed_evidence_and_find_siblings() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/users.ts"),
            "app.get('/users', (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from users where name = ${q}`);\n});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/admin.ts"),
            "app.get('/admin', (req, res) => {\n  const q = req.query.q;\n  return db.query(`select * from admins where name = ${q}`);\n});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/safe.ts"),
            "app.get('/safe', (req, res) => {\n  const q = sanitize(req.query.q);\n  return db.query(`select * from safe where name = ${q}`);\n});\n",
        )
        .unwrap();
        let finding = Finding::new_tool(
            "agentic-sast",
            "js/sql-injection",
            "src/users.ts",
            3,
            Some(3),
            Severity::High,
            "req.query reaches db.query without sanitizer",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        let store = StaticEvidenceStore::open_in_memory().unwrap();
        let evidence = StaticEvidenceNode::new(
            crate::static_evidence::StaticEvidenceNodeKind::CodeSpan,
            "confirmed SQL flow",
            "const q = req.query.q;\nreturn db.query(`select * from users where name = ${q}`);",
        )
        .with_finding_fingerprint(finding.fingerprint.clone())
        .with_source_span("src/users.ts", 2, Some(3));
        store.upsert_node(&evidence).unwrap();

        let report =
            hunt_whitebox_static_variants(temp.path(), &[finding], Some(&store), 10).unwrap();

        assert_eq!(report.patterns.len(), 1);
        assert_eq!(report.patterns[0].source_tokens, vec!["req.query"]);
        assert!(report.patterns[0]
            .sink_tokens
            .contains(&"db.query".to_string()));
        assert_eq!(report.count, 1);
        let variant = &report.variants[0];
        assert_eq!(variant.tool, "whitebox-variant-search");
        assert_eq!(variant.file_path, "src/admin.ts");
        assert_eq!(
            variant.static_proof_state,
            Some(StaticProofState::CodeCited)
        );
        assert_ne!(
            variant.static_proof_state,
            Some(StaticProofState::StaticallyConfirmed)
        );
        assert!(variant.message.contains("requires independent validation"));
    }

    #[test]
    fn whitebox_variants_ignore_non_confirmed_and_guarded_candidates() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/source.ts"),
            "const q = req.query.q;\nreturn db.query(q);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/sibling.ts"),
            "const q = validate(req.query.q);\nreturn db.query(q);\n",
        )
        .unwrap();
        let unconfirmed = Finding::new_tool(
            "semgrep",
            "js/sql-injection",
            "src/source.ts",
            2,
            Some(2),
            Severity::High,
            "req.query reaches db.query",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        let confirmed = unconfirmed
            .clone()
            .with_static_proof_state(StaticProofState::StaticallyConfirmed);

        let no_patterns =
            derive_whitebox_variant_patterns(&[unconfirmed], None).expect("pattern derivation");
        assert!(no_patterns.is_empty());

        let report = hunt_whitebox_static_variants(temp.path(), &[confirmed], None, 10).unwrap();

        assert_eq!(report.count, 0);
        assert!(report
            .patterns
            .iter()
            .all(|pattern| pattern.original_fingerprint != ""));
    }

    #[test]
    fn registry_dispatches_variant_lift_and_hunt_through_runtime() {
        let (_temp, workspace, store, fingerprint) = seeded_workspace();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = MockRuntime::new();

        let lift = registry
            .execute_tool_with_runtime(
                "variant:lift-pattern",
                json!({"fingerprint": fingerprint}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(lift.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            lift.pointer("/data/signature/sink").and_then(Value::as_str),
            Some("child_process.exec")
        );

        let hunt = registry
            .execute_tool_with_runtime(
                "variant:hunt",
                json!({"fingerprint": fingerprint, "maxFindings": 5}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(hunt.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            hunt.pointer("/data/variants")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
        assert!(hunt
            .pointer("/data/persisted/findingsDb")
            .and_then(Value::as_str)
            .is_some());
    }

    #[test]
    fn variant_hunt_rejects_non_true_positive_findings() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-variant", workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "demo",
            "src/app.ts",
            1,
            None,
            Severity::High,
            "demo",
        );
        let fingerprint = finding.fingerprint.clone();
        let finding_id = store.insert_finding("run-variant", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.4,
                    rationale: "not confirmed".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let result = run_variant_hunt(
            json!({"fingerprint": fingerprint}),
            &ctx,
            Some(&MockRuntime::new()),
        )
        .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(false));
        assert!(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap()
            .contains("confirmed TP"));
    }

    #[test]
    fn ndiff_fetch_uses_offline_fixture_and_selects_primary_patch() {
        let result = run_ndiff_fetch_cve(json!({
            "id": "CVE-2024-1234",
            "offline": true,
            "fixtures": {
                "CVE-2024-1234": {
                    "id": "CVE-2024-1234",
                    "description": "Missing bounds check allows OOB write.",
                    "cwes": ["CWE-787"],
                    "severity": "HIGH",
                    "cvssScore": 7.8,
                    "affected": [],
                    "patches": [{"url":"https://github.com/o/r/commit/abc1234","kind":"nvd"}],
                    "publishedAt": "2024-01-15T00:00:00.000Z",
                    "source": "nvd",
                    "raw": {}
                }
            }
        }))
        .unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            result
                .pointer("/data/primaryPatchUrl")
                .and_then(Value::as_str),
            Some("https://github.com/o/r/commit/abc1234")
        );
    }

    #[test]
    fn registry_dispatches_ndiff_extract_and_hunt_through_runtime() {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/parser.c"), "memcpy(dst, src, len);\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let runtime = MockRuntime::new();

        let extract = registry
            .execute_tool_with_runtime(
                "ndiff:extract-fix-pattern",
                json!({"patchText": "--- a/parser.c\n+++ b/parser.c\n+if (len > cap) return -1;\n"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(extract.get("ok").and_then(Value::as_bool), Some(true));
        let pattern = extract.pointer("/data/pattern").cloned().unwrap();

        let hunt = registry
            .execute_tool_with_runtime(
                "ndiff:hunt-variants",
                json!({"pattern": pattern, "advisoryId": "CVE-2024-1234"}),
                &ctx,
                Some(&runtime),
            )
            .unwrap();
        assert_eq!(hunt.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(
            hunt.pointer("/data/findings")
                .and_then(Value::as_array)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            hunt.pointer("/data/findings/0/rule_id")
                .and_then(Value::as_str),
            Some("n-day/CVE-2024-1234")
        );
        assert!(hunt
            .pointer("/data/persisted/findingsDb")
            .and_then(Value::as_str)
            .is_some());
    }

    #[test]
    fn ndiff_hunt_requires_explicit_model_without_fallback() {
        let temp = tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let err = run_ndiff_hunt_variants(
            json!({"pattern": {"fixShape":"guard","vulnerableShape":"unguarded"}}),
            &ctx,
            Some(&MockRuntime::new()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires an explicit model"));
    }
}
