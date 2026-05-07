use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::findings::{Finding, Severity};

use super::generic_findings::persist_tool_findings;
use super::support::should_skip_path;
use super::{
    builtin_module, dag, max_findings_option, opt, resolve_tool_target, string_input_any,
    target_option, tool_with_options, BuiltinModule, ModuleKind, OptionType, ToolExecutionContext,
};

pub(super) fn module() -> BuiltinModule {
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

pub(super) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "chrome-rce:scan" => scan(input, ctx),
        "chrome-rce:review-trigger" => review_trigger(input, ctx),
        _ => anyhow::bail!("unknown chrome-rce tool {name:?}"),
    }
}

fn scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "chrome-rce:scan target is not a directory: {}",
            target.display()
        );
    }
    let mut findings = Vec::new();
    collect_findings(&target, &target, &mut findings)?;
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    Ok(json!({
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
    }))
}

fn collect_findings(root: &Path, dir: &Path, findings: &mut Vec<Finding>) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if should_skip_path(&name.to_string_lossy()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_findings(root, &path, findings)?;
        } else if file_type.is_file() && is_source_path(root, &path) {
            let raw = fs::read(&path).unwrap_or_default();
            if raw.iter().take(4096).any(|byte| *byte == 0) {
                continue;
            }
            let text = String::from_utf8_lossy(&raw);
            if !text.contains("DuplicateHandle") {
                continue;
            }
            if text.contains("IsPseudoHandle")
                || text.contains("INVALID_HANDLE_VALUE")
                || text.contains("IsValidHandleValue")
                || text.contains("reinterpret_cast<intptr_t>")
            {
                continue;
            }
            for (index, line) in text.lines().enumerate() {
                if line.contains("DuplicateHandle") {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string();
                    findings.push(Finding::new_tool(
                        "chrome-rce",
                        "chrome-rce-mojo-broker-pseudohandle-reject",
                        relative,
                        (index + 1) as u32,
                        None,
                        Severity::High,
                        "::DuplicateHandle is called in a Chrome IPC/broker path without an obvious pseudo-handle reject. Anchored to CVE-2025-2783; reject Win32 pseudo-handles before duplicating peer-supplied handles.",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn is_source_path(root: &Path, path: &Path) -> bool {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp") {
        return false;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/");
    relative.contains("/ipc/")
        || relative.contains("/mojo/")
        || relative.contains("/services/")
        || relative.contains("/sandbox/")
        || relative.contains("broker")
}

fn review_trigger(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let Some(diff_base) = string_input_any(&input, &["diffBase", "diff_base"]) else {
        return Ok(json!({
            "ok": true,
            "output": "chrome-rce:review-trigger skipped: pass diffBase to enable PR hot-path review.",
            "data": {
                "target": target.display().to_string(),
                "count": 0,
                "findings": [],
            },
        }));
    };
    let changed = changed_files(&target, &diff_base)?;
    let findings = changed
        .iter()
        .filter_map(|file| hot_path_finding(file))
        .collect::<Vec<_>>();
    let persisted = persist_tool_findings("chrome-rce", &target, &findings, ctx)?;
    Ok(json!({
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
    }))
}

fn changed_files(target: &Path, diff_base: &str) -> Result<Vec<String>> {
    let verify = Command::new("git")
        .args(["rev-parse", "--verify", diff_base])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !verify.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger could not resolve diffBase {:?}: {}",
            diff_base,
            String::from_utf8_lossy(&verify.stderr).trim()
        );
    }
    let output = Command::new("git")
        .args(["diff", "--name-only", &format!("{diff_base}...HEAD")])
        .current_dir(target)
        .output()
        .with_context(|| "chrome-rce:review-trigger requires git; install git or omit diffBase")?;
    if !output.status.success() {
        anyhow::bail!(
            "chrome-rce:review-trigger git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn hot_path_finding(file: &str) -> Option<Finding> {
    let rule = hot_path_rule(file)?;
    Some(Finding::new_tool(
        "chrome-rce",
        rule.rule_id,
        file.to_string(),
        1,
        None,
        rule.severity,
        rule.message,
    ))
}

fn hot_path_rule(file: &str) -> Option<&'static HotPathRule> {
    HOT_PATH_RULES.iter().find(|rule| rule.matches(file))
}

#[derive(Clone, Copy)]
struct HotPathRule {
    matcher: HotPathMatcher,
    rule_id: &'static str,
    severity: Severity,
    message: &'static str,
}

impl HotPathRule {
    fn matches(&self, file: &str) -> bool {
        match self.matcher {
            HotPathMatcher::EndsWith(suffix) => file.ends_with(suffix),
            HotPathMatcher::Contains(fragment) => file.contains(fragment),
        }
    }
}

#[derive(Clone, Copy)]
enum HotPathMatcher {
    EndsWith(&'static str),
    Contains(&'static str),
}

const HOT_PATH_RULES: &[HotPathRule] = &[
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/maglev/maglev-phi-representation-selector.cc"),
        rule_id: "chrome-rce-hot-path-v8-maglev-phi-representation-selector",
        severity: Severity::High,
        message: "V8 Maglev phi representation selector changed; this path is anchored to CVE-2026-3910 and needs compiler-specialist review.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/maglev/"),
        rule_id: "chrome-rce-hot-path-v8-maglev",
        severity: Severity::Medium,
        message: "V8 Maglev IR path changed; review representation tracking and type narrowing against historical Chrome RCE shapes.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("v8/src/compiler/backend/arm64/"),
        rule_id: "chrome-rce-hot-path-v8-arm64-codegen",
        severity: Severity::Medium,
        message: "V8 ARM64 backend path changed; review cross-architecture register-width assumptions against CVE-2024-7965.",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/typer.cc"),
        rule_id: "chrome-rce-hot-path-v8-typer",
        severity: Severity::Medium,
        message: "V8 typer changed; review type narrowing and CheckMaps preservation against CVE-2025-6554-family issues.",
    },
    HotPathRule {
        matcher: HotPathMatcher::EndsWith("v8/src/compiler/redundancy-elimination.cc"),
        rule_id: "chrome-rce-hot-path-v8-redundancy-elimination",
        severity: Severity::Medium,
        message: "V8 redundancy elimination changed; review removed checks before object access against historical CheckMaps issues.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/src/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server",
        severity: Severity::High,
        message: "Dawn wire server path changed; review objects_.Get plus re-entrant call plus reuse patterns anchored to CVE-2026-5281-family UAFs.",
    },
    HotPathRule {
        matcher: HotPathMatcher::Contains("third_party/dawn/generator/templates/dawn/wire/server/"),
        rule_id: "chrome-rce-hot-path-dawn-wire-server-templates",
        severity: Severity::High,
        message: "Dawn wire server template changed; generated dispatcher code needs review for re-entrant pointer reuse.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_path_rules_preserve_ordered_specificity_and_unknown_paths() {
        let specific_maglev =
            hot_path_finding("src/v8/src/maglev/maglev-phi-representation-selector.cc").unwrap();
        assert_eq!(
            specific_maglev.rule_id,
            "chrome-rce-hot-path-v8-maglev-phi-representation-selector"
        );
        assert_eq!(specific_maglev.severity, Severity::High);

        let generic_maglev = hot_path_finding("src/v8/src/maglev/graph-builder.cc").unwrap();
        assert_eq!(generic_maglev.rule_id, "chrome-rce-hot-path-v8-maglev");
        assert_eq!(generic_maglev.severity, Severity::Medium);

        let dawn_template =
            hot_path_finding("third_party/dawn/generator/templates/dawn/wire/server/api.cpp")
                .unwrap();
        assert_eq!(
            dawn_template.rule_id,
            "chrome-rce-hot-path-dawn-wire-server-templates"
        );
        assert_eq!(dawn_template.severity, Severity::High);

        assert!(hot_path_finding("content/browser/unrelated.cc").is_none());
    }
}
