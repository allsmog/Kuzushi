use crate::wants_sast_runtime::wants_sast_runtime;
use anyhow::Result;
use kuzushi_core::WorkspaceTarget;
use std::path::Path;

pub(crate) fn reject_shell_only_run_dot(tool: &str) -> Result<()> {
    if tool == "." {
        anyhow::bail!(
            "`kuzushi run .` is shell-only because the terminal command has no focused module. Use `kuzushi shell`, then `use <module>` and `run .`; from a terminal run an explicit tool such as `kuzushi --target . run context:build --input '{{}}'`."
        );
    }
    Ok(())
}

pub(crate) fn run_tool_workspace(
    tool: &str,
    target: Option<&Path>,
) -> Result<Option<WorkspaceTarget>> {
    match target {
        Some(target) => Ok(Some(WorkspaceTarget::new(target)?)),
        None if tool_defaults_to_workspace(tool) => Ok(Some(WorkspaceTarget::new(".")?)),
        None => Ok(None),
    }
}

pub(crate) const WORKSPACE_TOOL_PREFIXES: &[&str] = &[
    "findings:",
    "context:",
    "recon:",
    "vendor-assessment:",
    "chrome-rce:",
    "vuln-scout:",
    "tob:",
    "shinsa:",
    "prompt-armor:",
    "x-ray:",
    "threat-model:",
    "randori:",
    "variant:",
    "ndiff:",
    "systems-hunt:",
];

pub(crate) const WORKSPACE_TOOL_NAMES: &[&str] = &[
    "carlini-threat-hunt:run",
    "agentic-sast:scan",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "taint-iris-next:catalog",
    "taint-iris-next:codeql-db",
    "triage:run",
    "verify:finding",
    "verify:exploit",
    "patch:finding",
    "context-lite:index",
    "full-mode:hunt",
    "classifier-gate:score",
    "deep-audit:run",
    "sast:scan",
    "semgrep:scan",
    "codeql:scan",
    "iac-scan:scan",
];

pub(crate) const FINDING_STORE_TOOL_PREFIXES: &[&str] =
    &["findings:", "chrome-rce:", "variant:", "systems-hunt:"];

pub(crate) const FINDING_STORE_TOOL_NAMES: &[&str] = &[
    "triage:run",
    "verify:finding",
    "verify:exploit",
    "patch:finding",
    "agentic-sast:scan",
    "carlini-threat-hunt:run",
    "vuln-scout:audit",
    "tob:audit",
    "shinsa:scan",
    "shinsa:quick-check",
    "shinsa:nist-scan",
    "shinsa:nist-quick-check",
    "prompt-armor:scan",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "ndiff:hunt-variants",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "sast:scan",
    "semgrep:scan",
    "codeql:scan",
    "iac-scan:scan",
];

pub(crate) const RUNTIME_TOOL_NAMES: &[&str] = &[
    "triage:run",
    "verify:finding",
    "patch:finding",
    "agentic-sast:scan",
    "carlini-threat-hunt:run",
    "vendor-assessment:assess",
    "vuln-scout:audit",
    "tob:audit",
    "shinsa:scan",
    "shinsa:quick-check",
    "shinsa:nist-scan",
    "shinsa:nist-quick-check",
    "prompt-armor:scan",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "variant:lift-pattern",
    "variant:hunt",
    "ndiff:extract-fix-pattern",
    "ndiff:hunt-variants",
    "systems-hunt:systems-invariant-extract",
    "systems-hunt:systems-trigger-synth",
    "systems-hunt:systems-hunt",
    "systems-hunt:deep-semantic-cwe-select",
    "systems-hunt:deep-semantic-hunt",
    "taint-iris:hunt",
    "taint-iris-next:hunt",
    "taint-iris-next:catalog",
    "taint-iris-next:codeql-db",
    "full-mode:hunt",
    "classifier-gate:score",
    "deep-audit:run",
    "smoke:next-step",
    "threat-model:build",
    "randori:pasta",
    "x-ray:run",
    "x-ray:x-ray",
];

pub(crate) fn tool_defaults_to_workspace(tool: &str) -> bool {
    has_known_prefix(tool, WORKSPACE_TOOL_PREFIXES) || has_known_name(tool, WORKSPACE_TOOL_NAMES)
}

pub(crate) fn tool_needs_finding_store(tool: &str) -> bool {
    has_known_prefix(tool, FINDING_STORE_TOOL_PREFIXES)
        || has_known_name(tool, FINDING_STORE_TOOL_NAMES)
}

pub(crate) fn tool_needs_runtime(tool: &str, input: &serde_json::Value) -> bool {
    has_known_name(tool, RUNTIME_TOOL_NAMES) || tool == "sast:scan" && wants_sast_runtime(input)
}

pub(crate) fn has_known_prefix(tool: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| tool.starts_with(prefix))
}

pub(crate) fn has_known_name(tool: &str, names: &[&str]) -> bool {
    names.contains(&tool)
}
