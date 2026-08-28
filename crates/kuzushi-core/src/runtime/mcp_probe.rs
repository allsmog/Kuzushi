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
        name: "findings",
        artifact_relative_path: ".kuzushi/v3/index.sqlite3",
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
        name: "cpg",
        artifact_relative_path: ".kuzushi/cpg-rs",
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

fn mcp_artifact_attachment(target: &Path, spec: &McpArtifactSpec) -> Result<Option<McpAttachment>> {
    match spec.name {
        "codeql" => managed_codeql_attachment(target),
        // Ready when at least one current-shape-version graph exists —
        // stale-version leftovers alone must not attach the server.
        "cpg" => {
            let path = target.join(spec.artifact_relative_path);
            Ok((artifact_state_within(target, &path).is_cached()
                && kuzushi_cpg::has_artifacts(target))
            .then(|| McpAttachment::new(spec.name, path.display().to_string())))
        }
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
mod tests {
    use super::*;

    #[test]
    fn empty_target_returns_only_constants() {
        let tmp = tempfile::tempdir().unwrap();
        let plan = mcp_attachment_plan_for_target(tmp.path());
        assert_eq!(plan.len(), MCP_CONSTANT_NAMES.len());
        for name in MCP_CONSTANT_NAMES {
            assert!(plan_contains(&plan, name), "missing constant {name}");
        }
    }

    #[test]
    fn context_artifact_attaches_context_server() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            tmp.path().join(".kuzushi/context-snapshot.json"),
            "{\"target\":\"x\"}",
        )
        .unwrap();
        let plan = mcp_attachment_plan_for_target(tmp.path());
        assert!(plan_contains(&plan, "context"));
        // Other artifact-backed servers stay off.
        assert!(!plan_contains(&plan, "cpg"));
        assert!(!plan_contains(&plan, "codeql"));
    }

    #[test]
    fn stale_joern_cpg_bin_attaches_nothing() {
        // Pre-cutover targets may still carry a JVM-joern `.kuzushi/cpg.bin`;
        // it must not attach any server now that the joern MCP is deleted.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(tmp.path().join(".kuzushi/cpg.bin"), b"CPG\0bin").unwrap();
        let plan = mcp_attachment_plan_for_target(tmp.path());
        assert_eq!(plan.len(), MCP_CONSTANT_NAMES.len());
    }

    #[test]
    fn marker_only_codeql_database_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::workspace::workspace_codeql_db_path(tmp.path());
        std::fs::create_dir_all(db.join("db-rust")).unwrap();
        std::fs::write(db.join("codeql-database.yml"), "primaryLanguage: rust\n").unwrap();

        let error = try_mcp_attachment_plan_for_target(tmp.path())
            .unwrap_err()
            .to_string();
        let plan = mcp_attachment_plan_for_target(tmp.path());

        assert!(error.contains("trusted provenance"), "{error}");
        assert!(!plan_contains(&plan, "codeql"));
    }

    #[test]
    fn non_database_directory_does_not_attach_codeql_server() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::workspace::workspace_codeql_db_path(tmp.path());
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("placeholder"), "x").unwrap();

        let plan = mcp_attachment_plan_for_target(tmp.path());

        assert!(!plan_contains(&plan, "codeql"));
    }

    #[test]
    fn malformed_artifact_does_not_attach() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            tmp.path().join(".kuzushi/context-snapshot.json"),
            "{not json",
        )
        .unwrap();
        let plan = mcp_attachment_plan_for_target(tmp.path());
        assert!(!plan_contains(&plan, "context"));
    }

    #[test]
    fn plan_ordering_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(tmp.path().join(".kuzushi/context-snapshot.json"), "{}").unwrap();
        let first = mcp_attachment_plan_for_target(tmp.path());
        let second = mcp_attachment_plan_for_target(tmp.path());
        assert_eq!(first, second);
        let names: Vec<_> = first.iter().map(|a| a.name.as_str()).collect();
        // treesitter (constant) before any artifact-backed entry.
        let ts = names.iter().position(|n| *n == "treesitter").unwrap();
        let ctx = names.iter().position(|n| *n == "context").unwrap();
        assert!(ts < ctx);
    }
}
