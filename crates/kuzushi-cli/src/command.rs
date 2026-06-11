use clap::Subcommand;
use std::path::PathBuf;

mod pr_comment_args;
mod subcommands;
pub(crate) use pr_comment_args::PrCommentArgs;
pub(crate) use subcommands::{
    AuthCommand, ConfigCommand, FailOnArg, McpBackend, McpCommand, RunsCommand, ScanModeArg,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Start the interactive shell.
    Shell {
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Run configured scanners and persist findings.
    Scan {
        target: PathBuf,
        #[arg(long, value_enum)]
        mode: Option<ScanModeArg>,
        #[arg(long, value_delimiter = ',')]
        tasks: Vec<String>,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        triage: Option<bool>,
        #[arg(long)]
        json: bool,
        /// Emit one line per pipeline event in a deterministic, grep-friendly format.
        #[arg(long, conflicts_with = "json")]
        ci: bool,
        /// Per-operation USD budget caps, e.g. `triage=50,deep-audit=200,full-mode-multi=300`.
        /// Caps are persisted to the spend ledger and enforced before each LLM call
        /// once the runtime is wired through (Phase 4+). Set without value to clear all caps.
        #[arg(long)]
        budget: Option<String>,
        /// Diff-scope the scan to files changed since `<ref>`. Engines that
        /// support it (full-mode-multi today) narrow their walk; others are
        /// unaffected. Pass `--include-worktree` to include uncommitted edits.
        #[arg(long)]
        since: Option<String>,
        /// When `--since` is set, also include uncommitted (working-tree) changes.
        #[arg(long, requires = "since")]
        include_worktree: bool,
        /// Exit with code 3 when any finding at or above this severity is
        /// recorded by the scan. Lets CI block a PR on findings; without it
        /// the scan exits 0 regardless of what it found.
        #[arg(long, value_enum)]
        fail_on: Option<FailOnArg>,
        /// Write a SARIF 2.1.0 export of this workspace's findings to the
        /// given path after the scan (for GitHub Code Scanning upload etc.).
        #[arg(long)]
        sarif: Option<PathBuf>,
    },
    /// List persisted findings.
    Findings {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, value_delimiter = ',')]
        severity: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        verdict: Vec<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "file-path")]
        file_path: Option<String>,
        /// Filter by discovery channel: sarif, ainalysis, ainalysis-multi,
        /// diff-analyzer, infer, fuzzing. Comma- or repeat-separated.
        #[arg(long = "vuln-source", value_delimiter = ',')]
        vuln_source: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect one persisted finding by alias, fingerprint, or fingerprint prefix.
    Finding {
        reference: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect replayable run artifacts under `.kuzushi/runs`.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Add an expiring, evidence-backed suppression for a finding.
    Suppress {
        reference: String,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "operator")]
        author: String,
        #[arg(long, default_value_t = 90)]
        days: u64,
        #[arg(long)]
        json: bool,
    },
    /// List whitebox/static suppressions and their audit store.
    Suppressions {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show the current CLI/shell permission and sandbox policy summary.
    Permissions {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect or initialize config.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Diagnostic credential subcommands. For interactive OAuth login,
    /// use `kuzushi shell` then `auth login openai` or
    /// `auth login anthropic`.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// List native modules.
    Modules {
        #[arg(long)]
        json: bool,
    },
    /// List native tools.
    Tools {
        #[arg(long)]
        json: bool,
    },
    /// Run Rust CLI preflight diagnostics.
    Doctor {
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Execute a native tool descriptor-backed command. Use an explicit
    /// `module:tool`; shell-only `run .` needs focused module state.
    Run {
        tool: String,
        #[arg(long, default_value = "{}")]
        input: String,
        /// Override a canonical tool option. Repeat as `--option key=value`.
        #[arg(long = "option")]
        options: Vec<String>,
    },
    /// Run a local MCP server (joern, clang, or gtags) over stdio.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Build a Kuzushi PR comment from persisted run artifacts.
    PrComment(PrCommentArgs),
}
