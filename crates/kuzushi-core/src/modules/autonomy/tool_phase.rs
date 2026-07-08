//! Declarative, name-based tool → engagement-phase classification.
//!
//! Mirrors the shape of `runtime_requirements.rs`: flat name/prefix tables,
//! not branchy logic. This is the single authoritative "how far along the
//! 組→崩→作→掛 spine does a tool sit" table that the autonomy gate consumes to
//! decide whether the current posture authorizes a tool at all.
//!
//! A tool that classifies as [`ToolClassification::Read`] is infra/inspect
//! (help, config, findings reads, navigation, workspace status) — always
//! allowed, posture-independent. A tool that classifies to a
//! [`WorkflowPhase`] is gated: it may only run when the posture ceiling is at
//! or above that phase.
//!
//! `classify` returns `None` only for a tool name whose module prefix is
//! unknown to every table. That is a *permissive* runtime outcome (the gate
//! treats it as always-allowed), but the guard test
//! `every_registered_tool_is_classified` fails on it so a newly-registered
//! mutating tool cannot silently escape gating.

use super::WorkflowPhase;

/// How a tool relates to the engagement spine for autonomy gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClassification {
    /// Infra / read / inspect — always allowed regardless of posture.
    Read,
    /// A phase-bearing action, gated by the posture ceiling.
    Phase(WorkflowPhase),
}

/// Modules whose every verb is infra/read/navigation (no target effect that
/// autonomy should ever gate).
const READ_MODULE_PREFIXES: &[&str] = &[
    "catalog:",
    "config:",
    "engagement:",
    "findings:",
    "module-recommender:",
    "router:",
    "threat-leads:",
    "workspace:",
];

/// Verbs that are pure reads/inspections even on an action module (e.g.
/// `threat-model:read`, `x-ray:read`, `taint-iris-next:catalog`). Matched on
/// the segment after the module id, so they always resolve to `Read`.
const READ_VERBS: &[&str] = &[
    "catalog",
    "config",
    "diff",
    "fetch-cve",
    "frameworks",
    "list",
    "methodologies",
    "read",
    "report",
    "show",
    "skills",
    "status",
];

/// Module id → phase ceiling. The gate compares `Phase(p)` against the
/// posture ceiling; a tool may run only when `p <= ceiling`. Kept exhaustive
/// over the registered module set — the guard test proves no registered tool
/// falls through unclassified.
fn phase_for_module(module_id: &str) -> Option<WorkflowPhase> {
    let phase = match module_id {
        // 組 map — context gathering & analysis-artifact building.
        "context" | "context-lite" | "cpg" | "codeql-db" | "entry-points" | "threat-model"
        | "threat-intel" | "x-ray" | "recon" | "bounty" | "wasm-plugin" => WorkflowPhase::Map,
        // 崩 hunt — vulnerability discovery.
        "agentic-sast" | "android-apk" | "cargo-audit" | "carlini-threat-hunt" | "chrome-rce"
        | "classifier-gate" | "codeql" | "deep-audit" | "dep-hygiene" | "exploit-chain"
        | "full-mode" | "govulncheck" | "iac-scan" | "license-scan" | "ndiff" | "offense"
        | "offense-review" | "pipeline" | "prompt-armor" | "pwn" | "randori" | "sast"
        | "sbom-scan" | "secret-scan" | "semgrep" | "shinsa" | "systems-hunt" | "taint-iris"
        | "taint-iris-next" | "tob" | "uaf-hunt" | "variant" | "vendor-assessment"
        | "vuln-scout" => WorkflowPhase::Hunt,
        // 作 confirm — triage & verify.
        "triage" | "verify" => WorkflowPhase::Confirm,
        // 掛 fix — patch & report.
        "patch" | "report" => WorkflowPhase::Fix,
        _ => return None,
    };
    Some(phase)
}

/// Exact tool names whose phase differs from their module default.
/// `codeql:create-db` builds a reusable analysis artifact (map) even though
/// `codeql:scan` is a hunt action. `pwn:reverse` disassembles/profiles a
/// binary into an analysis artifact (map) even though the rest of the `pwn`
/// module (`exploit-run`, `auto-solve`, …) are hunt/mutating actions; this
/// mirrors the onboarding walker's own `PlanningTaskId::ReverseEngineerBinary`
/// classification (`crates/kuzushi-tui/src/app/onboarding/task_id.rs`), which
/// a drift test cross-checks against this table.
fn phase_override(tool_name: &str) -> Option<WorkflowPhase> {
    match tool_name {
        "codeql:create-db" | "pwn:reverse" => Some(WorkflowPhase::Map),
        _ => None,
    }
}

fn module_id(tool_name: &str) -> &str {
    tool_name.split_once(':').map(|(id, _)| id).unwrap_or(tool_name)
}

fn verb(tool_name: &str) -> Option<&str> {
    tool_name.split_once(':').map(|(_, verb)| verb)
}

fn is_read_tool(tool_name: &str) -> bool {
    if READ_MODULE_PREFIXES
        .iter()
        .any(|prefix| tool_name.starts_with(prefix))
    {
        return true;
    }
    verb(tool_name).is_some_and(|verb| READ_VERBS.contains(&verb))
}

/// Classify a tool for autonomy gating. `None` = unknown module prefix; the
/// gate treats that permissively, but the guard test forbids it for any
/// registered tool.
pub fn classify(tool_name: &str) -> Option<ToolClassification> {
    if is_read_tool(tool_name) {
        return Some(ToolClassification::Read);
    }
    if let Some(phase) = phase_override(tool_name) {
        return Some(ToolClassification::Phase(phase));
    }
    phase_for_module(module_id(tool_name)).map(ToolClassification::Phase)
}

/// The engagement phase a tool acts in, or `None` for read/infra tools that
/// are always allowed regardless of posture. This is what the gate consumes.
pub fn tool_phase(tool_name: &str) -> Option<WorkflowPhase> {
    match classify(tool_name) {
        Some(ToolClassification::Phase(phase)) => Some(phase),
        Some(ToolClassification::Read) | None => None,
    }
}

/// Tools that mutate target/repo state (write patches, execute exploits).
/// Drives the advisory `RequireApproval` decision at/under the ceiling. The
/// interactive prompt itself is owned by the TUI's existing approval gate;
/// this only classifies which permitted actions warrant one.
const MUTATING_TOOL_NAMES: &[&str] = &["patch:finding"];
const MUTATING_TOOL_PREFIXES: &[&str] = &["pwn:", "offense:", "exploit-chain:"];

pub fn tool_mutates(tool_name: &str) -> bool {
    MUTATING_TOOL_NAMES.contains(&tool_name)
        || MUTATING_TOOL_PREFIXES
            .iter()
            .any(|prefix| tool_name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representative_tool_per_phase() {
        assert_eq!(tool_phase("context:build"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("x-ray:run"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("semgrep:scan"), Some(WorkflowPhase::Hunt));
        assert_eq!(tool_phase("taint-iris-next:hunt"), Some(WorkflowPhase::Hunt));
        assert_eq!(tool_phase("triage:run"), Some(WorkflowPhase::Confirm));
        assert_eq!(tool_phase("verify:finding"), Some(WorkflowPhase::Confirm));
        assert_eq!(tool_phase("patch:finding"), Some(WorkflowPhase::Fix));
        assert_eq!(tool_phase("report:build"), Some(WorkflowPhase::Fix));
    }

    #[test]
    fn infra_and_read_tools_are_posture_independent() {
        assert_eq!(tool_phase("config:show"), None);
        assert_eq!(tool_phase("catalog:tools"), None);
        assert_eq!(tool_phase("findings:list"), None);
        assert_eq!(tool_phase("workspace:status"), None);
        // Read verbs on action modules still classify as read.
        assert_eq!(classify("threat-model:read"), Some(ToolClassification::Read));
        assert_eq!(classify("x-ray:read"), Some(ToolClassification::Read));
        assert_eq!(
            classify("taint-iris-next:catalog"),
            Some(ToolClassification::Read)
        );
        assert_eq!(classify("shinsa:frameworks"), Some(ToolClassification::Read));
    }

    #[test]
    fn codeql_db_build_is_a_map_action_not_a_hunt() {
        assert_eq!(tool_phase("codeql:create-db"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("codeql:scan"), Some(WorkflowPhase::Hunt));
    }

    #[test]
    fn pwn_reverse_is_a_map_action_not_a_hunt() {
        assert_eq!(tool_phase("pwn:reverse"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("pwn:exploit-run"), Some(WorkflowPhase::Hunt));
    }

    #[test]
    fn mutating_tools_are_flagged() {
        assert!(tool_mutates("patch:finding"));
        assert!(tool_mutates("pwn:exploit-run"));
        assert!(tool_mutates("offense:chain"));
        assert!(!tool_mutates("semgrep:scan"));
        assert!(!tool_mutates("triage:run"));
        assert!(!tool_mutates("report:build"));
    }

    #[test]
    fn unknown_module_prefix_is_unclassified() {
        assert_eq!(classify("brand-new-module:do-thing"), None);
    }
}
