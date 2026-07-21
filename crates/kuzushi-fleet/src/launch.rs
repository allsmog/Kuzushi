use crate::config::RemoteBox;
use crate::doctor::{doctor, shq};
use crate::stage::live_sessions;
use crate::transport::Transport;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchReport {
    pub remote: String,
    pub started_sessions: Vec<String>,
    pub already_live: Vec<String>,
}

/// Start the rolling queue in tmux, one session per free slot. Refuses when
/// doctor fails (the gate, not advice). Existing live sessions are left
/// alone — launch tops up to `slots`, it never doubles up.
pub fn launch(
    transport: &dyn Transport,
    remote: &RemoteBox,
    queue_command: &str,
) -> Result<LaunchReport> {
    let report = doctor(transport, remote)?;
    anyhow::ensure!(
        report.passed(),
        "doctor failed on {} — refusing launch:\n{}",
        remote.name,
        failed_checks(&report)
    );
    let live = live_sessions(transport, remote)?;
    let mut started = Vec::new();
    for slot in free_slots(remote, &live) {
        let session = format!("{}-{slot}", remote.session_prefix);
        transport.run(remote, &new_session_command(remote, &session, queue_command))?;
        started.push(session);
    }
    Ok(LaunchReport {
        remote: remote.name.clone(),
        started_sessions: started,
        already_live: live,
    })
}

fn failed_checks(report: &crate::doctor::DoctorReport) -> String {
    report
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| format!("  FAIL {}: {}", check.name, check.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn free_slots(remote: &RemoteBox, live: &[String]) -> Vec<usize> {
    (0..remote.slots)
        .filter(|slot| {
            let session = format!("{}-{slot}", remote.session_prefix);
            !live.iter().any(|existing| *existing == session)
        })
        .collect()
}

fn new_session_command(remote: &RemoteBox, session: &str, queue_command: &str) -> String {
    format!(
        "tmux new-session -d -s {} 'cd {} && {}'",
        shq(session),
        shq(&remote.workdir),
        queue_command,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote() -> RemoteBox {
        RemoteBox {
            name: "devpod".to_string(),
            ssh: "u@devpod".to_string(),
            workdir: "/home/u/kz-fleet".to_string(),
            slots: 3,
            session_prefix: "kz-fleet".to_string(),
        }
    }

    #[test]
    fn launch_tops_up_free_slots_without_doubling_live_sessions() {
        let live = vec!["kz-fleet-1".to_string(), "unrelated".to_string()];
        assert_eq!(free_slots(&remote(), &live), vec![0, 2]);
    }

    #[test]
    fn fully_occupied_box_gets_no_new_sessions() {
        let live = vec![
            "kz-fleet-0".to_string(),
            "kz-fleet-1".to_string(),
            "kz-fleet-2".to_string(),
        ];
        assert!(free_slots(&remote(), &live).is_empty());
    }
}
