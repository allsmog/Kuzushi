use anyhow::Result;
use clap::{Parser, Subcommand};
use kuzushi_fleet::config::{default_fleet_dir, find_remote, load_remotes};
use kuzushi_fleet::{SshTransport, Transport};
use std::path::PathBuf;

/// Remote execution plane for kuzushi fleets. Transport only: scanning
/// judgment lives in the engine this crate ships and launches.
#[derive(Parser)]
#[command(name = "kuzushi-fleet", version)]
struct Cli {
    /// Fleet config/state directory (default: ~/.kuzushi/v3/fleet).
    #[arg(long, global = true)]
    fleet_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Preflight a remote box; launch refuses on any FAIL.
    Doctor { remote: String },
    /// Ship the pinned engine (and optional queue file) to a box.
    Stage {
        remote: String,
        /// Local engine binary to ship.
        #[arg(long)]
        engine: PathBuf,
        /// Optional queue file to ship alongside.
        #[arg(long)]
        queue: Option<PathBuf>,
        /// Re-stage even over live sessions (never overrides the
        /// stale-checkout refusal).
        #[arg(long)]
        force: bool,
    },
    /// Start the rolling queue in tmux, one session per free slot.
    Launch {
        remote: String,
        /// Command each slot runs inside the staged workdir.
        #[arg(long, default_value = "./kz campaign run --queue queue.json >> queue.log 2>&1")]
        queue_command: String,
    },
    /// Sessions, live engine processes (zombie-aware), and queue-log tail.
    Status { remote: String },
    /// Pull recent run artifacts into the local inbox with a MANIFEST.
    Pull {
        remote: String,
        /// Override the recency cutoff in hours (default 24).
        #[arg(long)]
        max_age_hours: Option<u64>,
        /// Pull everything regardless of age.
        #[arg(long)]
        all: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let fleet_dir = match &cli.fleet_dir {
        Some(dir) => dir.clone(),
        None => default_fleet_dir()?,
    };
    let remotes = load_remotes(&fleet_dir)?;
    let transport = SshTransport;
    let output = run_verb(&cli.command, &remotes, &transport, &fleet_dir)?;
    println!("{output}");
    Ok(())
}

fn run_verb(
    verb: &Verb,
    remotes: &[kuzushi_fleet::RemoteBox],
    transport: &dyn Transport,
    fleet_dir: &std::path::Path,
) -> Result<String> {
    match verb {
        Verb::Doctor { remote } => {
            let report = kuzushi_fleet::doctor::doctor(transport, find_remote(remotes, remote)?)?;
            anyhow::ensure!(report.passed(), "{}", pretty(&report)?);
            pretty(&report)
        }
        Verb::Stage {
            remote,
            engine,
            queue,
            force,
        } => pretty(&kuzushi_fleet::stage::stage(
            transport,
            find_remote(remotes, remote)?,
            engine,
            queue.as_deref(),
            *force,
        )?),
        Verb::Launch {
            remote,
            queue_command,
        } => pretty(&kuzushi_fleet::launch::launch(
            transport,
            find_remote(remotes, remote)?,
            queue_command,
        )?),
        Verb::Status { remote } => {
            pretty(&kuzushi_fleet::status::status(transport, find_remote(remotes, remote)?)?)
        }
        Verb::Pull {
            remote,
            max_age_hours,
            all,
        } => pretty(&kuzushi_fleet::pull::pull(
            transport,
            find_remote(remotes, remote)?,
            &fleet_dir.join("inbox"),
            pull_cutoff(*max_age_hours, *all),
        )?),
    }
}

fn pull_cutoff(max_age_hours: Option<u64>, all: bool) -> Option<u64> {
    if all {
        return None;
    }
    Some(max_age_hours.unwrap_or(kuzushi_fleet::pull::DEFAULT_MAX_AGE_HOURS))
}

fn pretty<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string_pretty(value)?)
}
