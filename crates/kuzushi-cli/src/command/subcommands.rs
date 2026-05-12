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
        #[arg(value_enum)]
        backend: McpBackend,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RunsCommand {
    /// List run summaries.
    List {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show one run summary.
    Show {
        run_id: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print a run's trace JSONL.
    Trace {
        run_id: String,
        #[arg(long)]
        target: Option<PathBuf>,
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
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigCommand {
    /// Print the effective config.
    Show,
    /// Write the global config if it does not already exist.
    Init {
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
        /// Model spec to use for the ping. Default: ctx.config.model or anthropic:claude-haiku-4-5.
        #[arg(long)]
        model: Option<String>,
    },
}
