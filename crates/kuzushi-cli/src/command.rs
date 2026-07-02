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
        /// Workspace/repository to scan. Optional when the global `--target`
        /// is set; pass `.` for the current directory.
        target: Option<PathBuf>,
        /// Scan mode: `standard` or `whitebox-static`.
        #[arg(long, value_enum)]
        mode: Option<ScanModeArg>,
        /// Restrict the scan to these DAG tasks (comma- or repeat-separated).
        #[arg(long, value_delimiter = ',')]
        tasks: Vec<String>,
        /// Run model-backed triage on recorded findings after the scan.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        triage: Option<bool>,
        /// Emit the scan result as a single machine-readable JSON object.
        #[arg(long)]
        json: bool,
        /// Emit one line per pipeline event in a deterministic, grep-friendly format.
        #[arg(long, conflicts_with = "json")]
        ci: bool,
        /// Per-operation USD budget caps, e.g. `triage=50,deep-audit=200,full-mode-multi=300`.
        /// Caps are persisted to the spend ledger and enforced by spend-aware
        /// model-backed operations before they reserve estimated LLM spend.
        /// Scanner-only work and tools that do not report spend are unaffected.
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
        /// Maximum number of findings to list.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Filter by severity (critical, high, medium, low, info). Comma- or repeat-separated.
        #[arg(long, value_delimiter = ',')]
        severity: Vec<String>,
        /// Filter by triage verdict (e.g. confirmed, rejected, untriaged). Comma- or repeat-separated.
        #[arg(long, value_delimiter = ',')]
        verdict: Vec<String>,
        /// Filter by finding alias or rule name.
        #[arg(long)]
        name: Option<String>,
        /// Filter by source file path substring.
        #[arg(long = "file-path")]
        file_path: Option<String>,
        /// Filter by discovery channel: sarif, ainalysis, ainalysis-multi,
        /// diff-analyzer, infer, fuzzing. Comma- or repeat-separated.
        #[arg(long = "vuln-source", value_delimiter = ',')]
        vuln_source: Vec<String>,
        /// Emit the findings list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect one persisted finding by alias, fingerprint, or fingerprint prefix.
    Finding {
        /// Finding alias (F-0001), full fingerprint, or fingerprint prefix.
        reference: String,
        /// Emit the finding as machine-readable JSON.
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
        /// Finding alias, fingerprint, or fingerprint prefix to suppress.
        reference: String,
        /// Why this finding is being suppressed (recorded in the audit store).
        #[arg(long)]
        reason: String,
        /// Operator recorded as the author of the suppression.
        #[arg(long, default_value = "operator")]
        author: String,
        /// Days until the suppression expires and the finding resurfaces.
        #[arg(long, default_value_t = 90)]
        days: u64,
        /// Emit the result as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List whitebox/static suppressions and their audit store.
    Suppressions {
        /// Emit the suppressions list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the current CLI/shell permission and sandbox policy summary.
    Permissions {
        /// Emit the policy summary as machine-readable JSON.
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
        /// Emit the module list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List native tools.
    Tools {
        /// Emit the tool list as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run Rust CLI preflight diagnostics.
    Doctor {
        /// Emit the diagnostics report as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan a vendored vulnerable fixture offline — no API key, no model,
    /// no external scanners. A real finding with evidence in seconds.
    Demo {
        #[arg(long)]
        json: bool,
    },
    /// Execute a native tool descriptor-backed command. Use an explicit
    /// `module:tool`; shell-only `run .` needs focused module state.
    Run {
        /// Tool to execute, as `module:tool` (e.g. `context:build`).
        tool: String,
        /// Tool input as JSON. Use `@path` to read a file or `-` to read stdin.
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
