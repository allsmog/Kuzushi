use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ScanModeArg {
    Standard,
    WhiteboxStatic,
}

impl ScanModeArg {
    pub(crate) fn as_input_value(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WhiteboxStatic => "whitebox-static",
        }
    }
}

/// Severity threshold for `scan --fail-on`. Findings with unknown severity
/// never trip the gate (see `scan_gate::severity_gate_rank`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FailOnArg {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnArg {
    pub(crate) fn as_severity(self) -> kuzushi_core::Severity {
        match self {
            Self::Low => kuzushi_core::Severity::Low,
            Self::Medium => kuzushi_core::Severity::Medium,
            Self::High => kuzushi_core::Severity::High,
            Self::Critical => kuzushi_core::Severity::Critical,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum McpCommand {
    /// Run an MCP server over stdio. Speaks JSON-RPC 2.0 newline-delimited.
    Serve {
        /// Which backend to serve.
        #[arg(value_enum)]
        backend: McpBackend,
    },
    /// Print a JSON health summary for the chosen backend (no MCP loop).
    Health {
        /// Which backend to inspect.
        #[arg(value_enum)]
        backend: McpBackend,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum KwpCommand {
    /// Approve a local file:// dynamic module by digest in kuzushi.lock.
    Approve {
        /// Dynamic module specifier, usually file:///absolute/path/module.mjs.
        specifier: String,
        /// Grant file as JSON or TOML. Omitted means no privileged grants.
        #[arg(long)]
        grant: Option<PathBuf>,
        /// Lockfile path. Defaults to ./kuzushi.lock.
        #[arg(long)]
        lockfile: Option<PathBuf>,
        /// Operator-visible module approval version.
        #[arg(long, default_value = "0.0.0")]
        version: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Mark an approved module digest as revoked in kuzushi.lock.
    Revoke {
        /// Digest key, for example sha256:<hex>.
        digest: String,
        /// Lockfile path. Defaults to ./kuzushi.lock.
        #[arg(long)]
        lockfile: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a dynamic module's resolved digest and lock status.
    Inspect {
        /// Dynamic module specifier, usually file:///absolute/path/module.mjs.
        specifier: String,
        /// Lockfile path. Defaults to ./kuzushi.lock.
        #[arg(long)]
        lockfile: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a lockfile audit summary.
    Audit {
        /// Lockfile path. Defaults to ./kuzushi.lock.
        #[arg(long)]
        lockfile: Option<PathBuf>,
        /// Target workspace containing `.kuzushi/v3/runs/<run-id>/kwp-audit.jsonl`.
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Include KWP audit records for this run id.
        #[arg(long)]
        run_id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RunsCommand {
    /// List run summaries.
    List {
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Filter by run status: running, completed, failed, canceled, interrupted, partial, skipped.
        #[arg(long, value_delimiter = ',')]
        status: Vec<String>,
        /// Emit the run list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show one run summary.
    Show {
        /// Run id under the target's `.kuzushi/v3/runs` directory.
        run_id: String,
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Emit the run summary as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a run's trace JSONL.
    Trace {
        /// Run id under the target's `.kuzushi/v3/runs` directory.
        run_id: String,
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Emit parsed trace events as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Compare finding snapshots from two runs.
    Diff {
        /// Baseline run id.
        base_run_id: String,
        /// Comparison run id.
        compare_run_id: String,
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Emit the diff as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Delete old run artifact directories.
    Prune {
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Delete runs older than this many days.
        #[arg(long = "older-than-days")]
        older_than_days: Option<u64>,
        /// Keep the newest N runs even if they match the age filter.
        #[arg(long = "keep-last")]
        keep_last: Option<usize>,
        /// Report what would be deleted without removing files.
        #[arg(long)]
        dry_run: bool,
        /// Emit the prune report as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum McpBackend {
    Gtags,
    Clang,
    Joern,
    /// Tree-sitter syntax-aware queries (node_at, query, callers).
    /// Pure-Rust, sub-10ms per call so the agent can invoke it freely
    /// during a hunt to verify candidates.
    TreeSitter,
    /// CodeQL CWE-folder selectors over a built database. Slow per
    /// call today (DB reload) but produces real reaching flows.
    Codeql,
    /// rev.ng binary reverse-engineering facts through Docker/Podman.
    Revng,
    /// Read-only context-snapshot.json queries (repo languages,
    /// attack surface, file index). Attaches only when the snapshot
    /// has been built.
    Context,
    /// Read-only entry-points.json queries (list, filter by framework
    /// or method).
    EntryPoints,
    /// Read-only threat-model.json queries (full doc, threats by
    /// severity, DFD elements).
    ThreatModel,
    /// Read-only threat-intel candidates.json queries (technologies,
    /// packages by ecosystem).
    ThreatIntel,
    /// Read-only x-ray markdown queries (summary, entry-points,
    /// invariants).
    XRay,
}

impl McpBackend {
    pub(crate) fn binary(self) -> &'static str {
        match self {
            Self::Gtags => "kuzushi-mcp-gtags",
            Self::Clang => "kuzushi-mcp-clang",
            Self::Joern => "kuzushi-mcp-joern",
            Self::TreeSitter => "kuzushi-mcp-treesitter",
            Self::Codeql => "kuzushi-mcp-codeql",
            Self::Revng => "kuzushi-mcp-revng",
            Self::Context => "kuzushi-mcp-context",
            Self::EntryPoints => "kuzushi-mcp-entry-points",
            Self::ThreatModel => "kuzushi-mcp-threat-model",
            Self::ThreatIntel => "kuzushi-mcp-threat-intel",
            Self::XRay => "kuzushi-mcp-x-ray",
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Print the effective config.
    Show,
    /// Write the global config if it does not already exist.
    Init {
        /// Overwrite an existing global config file.
        #[arg(long)]
        force: bool,
    },
    /// Print the global config path.
    Path,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommand {
    /// Round-trip a 1-token request to verify credentials, network, and bridge.
    Ping {
        /// Provider to ping. Default: anthropic.
        #[arg(default_value = "anthropic")]
        provider: String,
        /// Model spec to use for the ping. Default: ctx.config.model; no fallback is chosen.
        #[arg(long)]
        model: Option<String>,
    },
}
