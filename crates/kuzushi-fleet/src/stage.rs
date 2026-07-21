use crate::config::RemoteBox;
use crate::doctor::shq;
use crate::transport::Transport;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;
use std::process::Command;

/// Everything the stage guard judges, gathered up front so the decision is
/// pure and testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageGuardInputs {
    /// Commits the local engine checkout is behind its upstream, when the
    /// checkout has an upstream at all.
    pub behind_upstream: Option<u32>,
    /// Live fleet tmux sessions already on the box.
    pub live_sessions: Vec<String>,
    pub force: bool,
}

/// The two staging scars, enforced before any byte moves:
/// - never ship from a checkout that is behind its upstream (a stale local
///   engine once shipped over a fixed one),
/// - never re-stage over live sessions without `--force` (staging swaps the
///   binary under a running queue).
pub fn stage_guard(inputs: &StageGuardInputs) -> Result<()> {
    if let Some(behind) = inputs.behind_upstream {
        anyhow::ensure!(
            behind == 0,
            "local checkout is {behind} commit(s) behind its upstream — pull first \
             (staging a stale engine is how fixed bugs get re-shipped)"
        );
    }
    if !inputs.live_sessions.is_empty() && !inputs.force {
        anyhow::bail!(
            "live fleet session(s) on the box: {} — finish or kill them, or pass --force",
            inputs.live_sessions.join(", ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageReport {
    pub remote: String,
    pub shipped: Vec<String>,
}

/// Ship the engine binary (and optional queue file) to the box. Every
/// transfer is loud-fail via the transport contract.
pub fn stage(
    transport: &dyn Transport,
    remote: &RemoteBox,
    engine_binary: &Path,
    queue_file: Option<&Path>,
    force: bool,
) -> Result<StageReport> {
    let inputs = StageGuardInputs {
        behind_upstream: behind_upstream(engine_binary),
        live_sessions: live_sessions(transport, remote)?,
        force,
    };
    stage_guard(&inputs)?;
    transport.run(remote, &format!("mkdir -p {}", shq(&remote.workdir)))?;
    let mut shipped = Vec::new();
    push_file(transport, remote, engine_binary, "kz", &mut shipped)?;
    transport.run(remote, &format!("chmod +x {}/kz", shq(&remote.workdir)))?;
    if let Some(queue) = queue_file {
        push_file(transport, remote, queue, "queue.json", &mut shipped)?;
    }
    Ok(StageReport {
        remote: remote.name.clone(),
        shipped,
    })
}

fn push_file(
    transport: &dyn Transport,
    remote: &RemoteBox,
    local: &Path,
    remote_name: &str,
    shipped: &mut Vec<String>,
) -> Result<()> {
    anyhow::ensure!(local.is_file(), "{} does not exist", local.display());
    let destination = format!("{}/{remote_name}", remote.workdir);
    transport
        .push(remote, local, &destination)
        .with_context(|| format!("transfer of {} failed", local.display()))?;
    shipped.push(destination);
    Ok(())
}

/// `git rev-list HEAD..@{u} --count` in the binary's checkout, when it is
/// one. `None` when there is no repo or no upstream — nothing to judge.
fn behind_upstream(engine_binary: &Path) -> Option<u32> {
    let repo_dir = engine_binary.parent()?;
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["rev-list", "--count", "HEAD..@{u}"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

pub(crate) fn live_sessions(
    transport: &dyn Transport,
    remote: &RemoteBox,
) -> Result<Vec<String>> {
    let output = transport.run(
        remote,
        "tmux list-sessions -F '#S' 2>/dev/null || true",
    )?;
    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|session| session.starts_with(&remote.session_prefix))
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> StageGuardInputs {
        StageGuardInputs {
            behind_upstream: Some(0),
            live_sessions: Vec::new(),
            force: false,
        }
    }

    #[test]
    fn clean_checkout_and_idle_box_stage_freely() {
        assert!(stage_guard(&inputs()).is_ok());
        assert!(stage_guard(&StageGuardInputs {
            behind_upstream: None,
            ..inputs()
        })
        .is_ok());
    }

    #[test]
    fn behind_upstream_refuses_even_with_force() {
        let error = stage_guard(&StageGuardInputs {
            behind_upstream: Some(3),
            force: true,
            ..inputs()
        })
        .unwrap_err();

        assert!(error.to_string().contains("3 commit(s) behind"));
    }

    #[test]
    fn live_sessions_refuse_unless_forced() {
        let live = StageGuardInputs {
            live_sessions: vec!["kz-fleet-0".to_string()],
            ..inputs()
        };
        assert!(stage_guard(&live).unwrap_err().to_string().contains("kz-fleet-0"));

        assert!(stage_guard(&StageGuardInputs {
            force: true,
            ..live
        })
        .is_ok());
    }
}
