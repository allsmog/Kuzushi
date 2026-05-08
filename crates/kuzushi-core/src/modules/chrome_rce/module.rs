use super::*;
use crate::capabilities::chrome_rce::{changed_files, collect_findings, hot_path_finding};

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "chrome-rce",
        "Chrome RCE",
        ModuleKind::Defense,
        "Detection rules anchored to verified Chrome and Chromium RCE CVEs.",
        vec![
            tool_with_options(
                "chrome-rce:scan",
                "Scan for Chrome RCE bug patterns.",
                vec![target_option(), max_findings_option(50)],
            ),
            tool_with_options(
                "chrome-rce:review-trigger",
                "Review candidate Chrome RCE trigger paths.",
                vec![
                    target_option(),
                    opt(
                        "diffBase",
                        OptionType::String,
                        "Git reference for PR hot-path review.",
                    ),
                ],
            ),
        ],
        vec![
            dag("chrome-rce:scan", "findings", &["context:build"]),
            dag("chrome-rce:review-trigger", "review", &["chrome-rce:scan"]),
        ],
    )
}

pub(in crate::modules) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let handler = chrome_rce_handler(name)?;
    handler(input, ctx)
}

type ChromeRceHandler = fn(Value, &ToolExecutionContext<'_>) -> Result<Value>;

fn chrome_rce_handler(name: &str) -> Result<ChromeRceHandler> {
    CHROME_RCE_HANDLERS
        .iter()
        .find_map(|(tool_name, handler)| (*tool_name == name).then_some(*handler))
        .ok_or_else(|| anyhow::anyhow!("unknown chrome-rce tool {name:?}"))
}

const CHROME_RCE_HANDLERS: &[(&str, ChromeRceHandler)] = &[
    ("chrome-rce:scan", scan),
    ("chrome-rce:review-trigger", review_trigger),
];

pub(in crate::modules) fn scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = require_scan_target(&input, ctx)?;
    scan_target(&target, ctx)
}

fn scan_target(target: &std::path::Path, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let mut findings = Vec::new();
    collect_findings(target, target, &mut findings)?;
    let persisted = persist_tool_findings("chrome-rce", target, &findings, ctx)?;
    Ok(scan_response(target, findings, persisted))
}

fn require_scan_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<std::path::PathBuf> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "chrome-rce:scan target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

fn scan_response(
    target: &std::path::Path,
    findings: Vec<crate::findings::Finding>,
    persisted: impl serde::Serialize,
) -> Value {
    json!({
        "ok": true,
        "output": format!(
            "chrome-rce:scan found {} finding{} under {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            target.display()
        ),
        "data": {
            "target": target.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    })
}

pub(in crate::modules) fn review_trigger(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    review_trigger_for_target(&target, &input, ctx)
}

fn review_trigger_for_target(
    target: &std::path::Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let Some(diff_base) = string_input_any(&input, &["diffBase", "diff_base"]) else {
        return Ok(skipped_review_response(&target));
    };
    review_trigger_with_diff_base(target, &diff_base, ctx)
}

fn review_trigger_with_diff_base(
    target: &std::path::Path,
    diff_base: &str,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let changed = changed_files(target, diff_base)?;
    let findings = changed
        .iter()
        .filter_map(|file| hot_path_finding(file))
        .collect::<Vec<_>>();
    let persisted = persist_tool_findings("chrome-rce", target, &findings, ctx)?;
    Ok(review_response(
        target, diff_base, changed, findings, persisted,
    ))
}

fn skipped_review_response(target: &std::path::Path) -> Value {
    json!({
        "ok": true,
        "output": "chrome-rce:review-trigger skipped: pass diffBase to enable PR hot-path review.",
        "data": {
            "target": target.display().to_string(),
            "count": 0,
            "findings": [],
        },
    })
}

fn review_response(
    target: &std::path::Path,
    diff_base: &str,
    changed: Vec<String>,
    findings: Vec<crate::findings::Finding>,
    persisted: impl serde::Serialize,
) -> Value {
    json!({
        "ok": true,
        "output": format!(
            "chrome-rce:review-trigger matched {} hot path{} vs {}",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            diff_base
        ),
        "data": {
            "target": target.display().to_string(),
            "diffBase": diff_base,
            "changedFiles": changed,
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
    })
}
