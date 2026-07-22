use clap::Subcommand;
use std::path::PathBuf;

mod pr_comment_args;
mod subcommands;
pub(crate) use pr_comment_args::PrCommentArgs;
pub(crate) use subcommands::{
    AuthCommand, CampaignCommand, ConfigCommand, FailOnArg, KwpCommand, McpBackend, McpCommand,
    RunsCommand, ScanModeArg, SessionExportFormat, SessionsCommand,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Start the interactive shell.
    Shell {
        #[arg(long, help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
    },
    /// Run configured scanners and persist findings.
    Scan {
        #[arg(help = crate::support::TARGET_HELP)]
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
        /// Scan only the named shard from the shard manifest — a reusable,
        /// workspace-relative scope declared as `[shards.<name>] paths = [...]`
        /// in `<target>/.kuzushi/shards.toml` (or `--shard-manifest <file>`).
        /// Compiles into the canonical `sast:scan` `paths` option and records
        /// the shard name in run provenance.
        #[arg(long)]
        shard: Option<String>,
        /// Shard manifest file to resolve `--shard` against. Defaults to
        /// `<target>/.kuzushi/shards.toml`.
        #[arg(long, requires = "shard")]
        shard_manifest: Option<PathBuf>,
        /// Restrict the scan to these workspace-relative path roots (comma- or
        /// repeat-separated) without a manifest. Mutually exclusive with `--shard`.
        #[arg(long, value_delimiter = ',', conflicts_with = "shard")]
        paths: Vec<String>,
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
        /// Alias for --verdict using current review-decision terminology.
        #[arg(long, value_delimiter = ',')]
        decision: Vec<String>,
        /// Filter by terminal review decision completeness: open or complete.
        #[arg(long, value_delimiter = ',')]
        completeness: Vec<String>,
        /// Filter by lifecycle status, e.g. candidate, seen, runtime_verified, verified_static.
        #[arg(long, value_delimiter = ',')]
        status: Vec<String>,
        /// Filter by proof/confidence band: confirmed, likely, unverified, dismissed.
        /// Comma- or repeat-separated.
        #[arg(long, value_delimiter = ',')]
        confidence: Vec<String>,
        /// Filter by triage-lifecycle state: open, reviewing, confirmed, to_fix,
        /// dismissed, fixed, removed (or legacy untriaged/triaged).
        /// Comma- or repeat-separated.
        #[arg(long, value_delimiter = ',')]
        state: Vec<String>,
        /// Filter by finding alias or rule name.
        #[arg(long)]
        name: Option<String>,
        /// Filter by source file path substring.
        #[arg(long = "file-path")]
        file_path: Option<String>,
        /// Filter by discovery channel: sarif, analysis, analysis-multi,
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
    /// Record an append-only human review decision for a persisted finding.
    Decision {
        /// Finding alias (F-0001), full fingerprint, or fingerprint prefix.
        reference: String,
        /// Review decision: confirmed, rejected_false_positive, suppressed, deferred, accepted_risk, or needs_review.
        #[arg(long)]
        verdict: String,
        /// Human rationale recorded with the decision.
        #[arg(long)]
        reason: String,
        /// Emit the result as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Pipeline gate over persisted workspace state (no scan, no model
    /// calls): prints a plain findings/campaign/trend summary, writes a
    /// machine JSON summary, and exits 0 (clean), 1 (new confirmed findings
    /// at or above `--fail-on` vs the committed `.kuzushi/ci-baseline.json`),
    /// or 2 (error).
    Ci {
        #[arg(help = crate::support::TARGET_HELP)]
        target: Option<PathBuf>,
        /// Severity threshold for gating NEW confirmed findings.
        #[arg(long, value_enum, default_value = "low")]
        fail_on: FailOnArg,
        /// Rewrite `.kuzushi/ci-baseline.json` from the currently confirmed
        /// findings (accept current state) and exit 0. Commit the file.
        #[arg(long)]
        update_baseline: bool,
        /// JSON summary output path. Relative paths resolve under the target
        /// root; default `.kuzushi/v3/reports/ci-summary.json`.
        #[arg(long)]
        summary: Option<PathBuf>,
    },
    /// Inspect replayable run artifacts under `.kuzushi/v3/runs`.
    Runs {
        #[command(subcommand)]
        command: RunsCommand,
    },
    /// Inspect and manage global shell session transcripts.
    Sessions {
        #[command(subcommand)]
        command: SessionsCommand,
    },
    /// Export persisted workspace findings.
    Export {
        /// Export format: json, jsonl, sarif, csv, or markdown-bundle.
        #[arg(long)]
        format: Option<String>,
        /// Export findings by review-decision completeness: all, open, or complete.
        #[arg(long, default_value = "all")]
        completeness: String,
        /// Render the selected export to stdout without writing the output path.
        #[arg(long)]
        preview: bool,
        /// Permit writing a valid export when the selected completeness mode contains no findings.
        #[arg(long)]
        allow_empty: bool,
        /// Output file or bundle directory. Relative paths resolve under the target root.
        #[arg(long = "out")]
        output: PathBuf,
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
    /// no external scanners. Records scanner signals at the honest signal_only
    /// proof state without claiming source-grounded proof. The fixture is
    /// self-contained, so `--target` is ignored here.
    Demo {
        /// Emit the demo result as machine-readable JSON.
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
        /// Autonomy ceiling (`recon|scan|review|prove|fix`). Deprecated aliases:
        /// `hunt` = scan and `confirm` = prove. Refuses tools above the rung;
        /// omitted = unconstrained.
        #[arg(long)]
        autonomy: Option<String>,
        /// Caller-supplied run id (used by the campaign dispatcher). Must be
        /// unused; artifacts land at `.kuzushi/v3/runs/<run-id>/` so the
        /// caller finds them without racing directory scans.
        #[arg(long = "run-id")]
        run_id: Option<String>,
    },
    /// Campaign dispatcher: execute a planned job matrix as bounded
    /// `kuzushi run` child processes with retries, quota-wall pauses, and a
    /// budget cap.
    Campaign {
        #[command(subcommand)]
        command: CampaignCommand,
    },
    /// Run a local MCP server (cpg, clang, or gtags) over stdio.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Manage Kuzushi Worker Protocol approvals and audits.
    Kwp {
        #[command(subcommand)]
        command: KwpCommand,
    },
    /// Build a Kuzushi PR comment from persisted run artifacts.
    PrComment(PrCommentArgs),
}
