//! Build the per-call MCP attachment plan from on-disk artifact state.
//!
//! Each entry in [`MCP_ARTIFACT_TABLE`] names a kuzushi MCP server and
//! the artifact path (relative to the workspace root) that must exist
//! for the server to attach. The treesitter server is unconditional —
//! it operates directly on the source tree, so we include it whenever
//! a workspace target is set.
//!
//! Reused by `AgentToolPolicy::with_mcps_for_target` (kuzushi-core) and
//! by the shell's MCP-plan log line (kuzushi-tui).

use crate::runtime::domain::McpAttachment;
use crate::workspace::artifact_state_within;
use anyhow::Result;
use std::path::Path;

/// One row of [`MCP_ARTIFACT_TABLE`]. Static for simplicity — the set of
/// artifact-backed MCP servers is fixed at compile time.
#[derive(Debug, Clone, Copy)]
pub struct McpArtifactSpec {
    /// Server name (matches `kuzushi-mcp-<name>` binary). Stays
    /// camel-case-free so the bridge can derive
    /// `KUZUSHI_MCP_<NAME>_BIN` via uppercasing.
    pub name: &'static str,
    /// Artifact path relative to the workspace root. Probed via
    /// `artifact_state`; the MCP attaches only when state is `Cached`.
    pub artifact_relative_path: &'static str,
}

pub const MCP_ARTIFACT_TABLE: &[McpArtifactSpec] = &[
    McpArtifactSpec {
        name: "context",
        artifact_relative_path: ".kuzushi/context-snapshot.json",
    },
    McpArtifactSpec {
        name: "entry-points",
        artifact_relative_path: ".kuzushi/entry-points.json",
    },
    McpArtifactSpec {
        name: "threat-model",
        artifact_relative_path: ".kuzushi/threat-model.json",
    },
    McpArtifactSpec {
        name: "threat-intel",
        artifact_relative_path: ".kuzushi/threat-intel/candidates.json",
    },
    McpArtifactSpec {
        name: "x-ray",
        artifact_relative_path: "x-ray/x-ray.md",
    },
    McpArtifactSpec {
        name: "joern",
        artifact_relative_path: ".kuzushi/cpg.bin",
    },
    McpArtifactSpec {
        name: "codeql",
        artifact_relative_path: ".kuzushi/v3/codeql-db",
    },
];

/// Servers that attach whenever a workspace target is set, regardless
/// of artifact state. Treesitter operates directly on the source tree.
pub const MCP_CONSTANT_NAMES: &[&str] = &["treesitter"];

/// Build the MCP attachment plan for `target`. Entries are returned in
/// the canonical order from [`MCP_ARTIFACT_TABLE`] (constants first),
/// so callers can diff successive plans without flapping.
pub fn try_mcp_attachment_plan_for_target(target: &Path) -> Result<Vec<McpAttachment>> {
    let mut plan = constant_mcp_attachments();
    for spec in MCP_ARTIFACT_TABLE {
        if let Some(attachment) = mcp_artifact_attachment(target, spec)? {
            plan.push(attachment);
        }
    }
    Ok(plan)
}

/// Compatibility wrapper for callers that cannot surface probe errors yet.
/// It fails closed to constant, source-only MCPs and never attaches CodeQL
/// from a marker-only or otherwise invalid database.
pub fn mcp_attachment_plan_for_target(target: &Path) -> Vec<McpAttachment> {
    try_mcp_attachment_plan_for_target(target).unwrap_or_else(|_| constant_mcp_attachments())
}

fn constant_mcp_attachments() -> Vec<McpAttachment> {
    MCP_CONSTANT_NAMES
        .iter()
        .map(|name| McpAttachment::constant(*name))
        .collect()
}

fn mcp_artifact_attachment(
    target: &Path,
    spec: &McpArtifactSpec,
) -> Result<Option<McpAttachment>> {
    match spec.name {
        "codeql" => managed_codeql_attachment(target),
        _ => {
            let path = target.join(spec.artifact_relative_path);
            Ok(artifact_state_within(target, &path)
                .is_cached()
                .then(|| McpAttachment::new(spec.name, path.display().to_string())))
        }
    }
}

fn managed_codeql_attachment(target: &Path) -> Result<Option<McpAttachment>> {
    let expected = crate::workspace::workspace_codeql_db_path(target);
    let database = crate::codeql_repository_execution::resolve_managed_codeql_database(target)?;
    let Some(database) = database else {
        return Ok(None);
    };
    anyhow::ensure!(
        database.path() == expected,
        "managed CodeQL database resolved outside its workspace path"
    );
    Ok(Some(
        McpAttachment::new("codeql", database.path().display().to_string())
            .with_artifact_identity(database.database_identity()),
    ))
}

/// True if `plan` contains an entry with the given server `name`.
pub fn plan_contains(plan: &[McpAttachment], name: &str) -> bool {
    plan.iter().any(|attachment| attachment.name == name)
}

#[cfg(test)]
mod tests;
