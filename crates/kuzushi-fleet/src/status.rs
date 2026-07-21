use crate::config::RemoteBox;
use crate::doctor::shq;
use crate::stage::live_sessions;
use crate::transport::Transport;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub remote: String,
    pub sessions: Vec<String>,
    /// Live engine process count — the zombie-aware signal. A tmux session
    /// with zero engine processes is a shell waiting on nothing.
    pub engine_processes: usize,
    pub queue_log_tail: Vec<String>,
}

impl StatusReport {
    /// The "can I step away" answer this verb exists for.
    pub fn healthy(&self) -> bool {
        self.sessions.is_empty() || self.engine_processes > 0
    }
}

pub fn status(transport: &dyn Transport, remote: &RemoteBox) -> Result<StatusReport> {
    let sessions = live_sessions(transport, remote)?;
    let engine_processes = engine_process_count(transport, remote)?;
    let queue_log_tail = queue_log_tail(transport, remote)?;
    Ok(StatusReport {
        remote: remote.name.clone(),
        sessions,
        engine_processes,
        queue_log_tail,
    })
}

/// Count real engine processes, not tmux panes. `pgrep -f` on the staged
/// binary path: a devpod whose PID 1 is `sleep infinity` still reports its
/// true worker count this way.
fn engine_process_count(transport: &dyn Transport, remote: &RemoteBox) -> Result<usize> {
    let output = transport.run(
        remote,
        &format!("pgrep -fc {}/kz 2>/dev/null || echo 0", shq(&remote.workdir)),
    )?;
    Ok(output.stdout.trim().parse().unwrap_or(0))
}

fn queue_log_tail(transport: &dyn Transport, remote: &RemoteBox) -> Result<Vec<String>> {
    let output = transport.run(
        remote,
        &format!(
            "tail -n 5 {}/queue.log 2>/dev/null || true",
            shq(&remote.workdir)
        ),
    )?;
    Ok(output
        .stdout
        .lines()
        .map(str::to_string)
        .filter(|line| !line.trim().is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(sessions: &[&str], engines: usize) -> StatusReport {
        StatusReport {
            remote: "devpod".to_string(),
            sessions: sessions.iter().map(|session| session.to_string()).collect(),
            engine_processes: engines,
            queue_log_tail: Vec::new(),
        }
    }

    #[test]
    fn sessions_with_engines_or_a_quiet_box_are_healthy() {
        assert!(report(&["kz-fleet-0"], 2).healthy());
        assert!(report(&[], 0).healthy());
    }

    #[test]
    fn sessions_without_engine_processes_are_zombies_not_health() {
        assert!(!report(&["kz-fleet-0"], 0).healthy());
    }
}
