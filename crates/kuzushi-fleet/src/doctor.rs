use crate::config::RemoteBox;
use crate::transport::Transport;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub remote: String,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Launch is refused on any FAIL — doctor is a gate, not advice.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }
}

pub fn doctor(transport: &dyn Transport, remote: &RemoteBox) -> Result<DoctorReport> {
    let checks = vec![
        workdir_check(transport, remote)?,
        engine_check(transport, remote)?,
        disk_check(transport, remote)?,
        tmux_check(transport, remote)?,
    ];
    Ok(DoctorReport {
        remote: remote.name.clone(),
        checks,
    })
}

fn workdir_check(transport: &dyn Transport, remote: &RemoteBox) -> Result<DoctorCheck> {
    let output = transport.run(remote, &format!("test -d {}", shq(&remote.workdir)))?;
    Ok(check(
        "workdir",
        output.success(),
        if output.success() {
            remote.workdir.clone()
        } else {
            format!("{} missing — run stage first", remote.workdir)
        },
    ))
}

fn engine_check(transport: &dyn Transport, remote: &RemoteBox) -> Result<DoctorCheck> {
    let output = transport.run(
        remote,
        &format!("{}/kz --version 2>/dev/null || true", shq(&remote.workdir)),
    )?;
    let version = output.stdout.trim().to_string();
    Ok(check(
        "engine",
        !version.is_empty(),
        if version.is_empty() {
            "staged kz binary missing or not executable".to_string()
        } else {
            version
        },
    ))
}

fn disk_check(transport: &dyn Transport, remote: &RemoteBox) -> Result<DoctorCheck> {
    let output = transport.run(remote, "df -Pk / | awk 'NR==2 {print $4}'")?;
    let free_kb: u64 = output.stdout.trim().parse().unwrap_or(0);
    let free_gb = free_kb / (1024 * 1024);
    Ok(check(
        "disk",
        free_gb >= 5,
        format!("{free_gb} GiB free (need >= 5)"),
    ))
}

fn tmux_check(transport: &dyn Transport, remote: &RemoteBox) -> Result<DoctorCheck> {
    let output = transport.run(remote, "command -v tmux >/dev/null && echo ok")?;
    let present = output.stdout.trim() == "ok";
    Ok(check(
        "tmux",
        present,
        if present {
            "available".to_string()
        } else {
            "tmux not installed".to_string()
        },
    ))
}

fn check(name: &str, passed: bool, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        passed,
        detail,
    }
}

pub(crate) fn shq(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::CommandOutput;
    use std::cell::RefCell;

    pub(crate) struct FakeTransport {
        pub outputs: RefCell<Vec<CommandOutput>>,
        pub commands: RefCell<Vec<String>>,
    }

    impl FakeTransport {
        pub(crate) fn with_outputs(outputs: Vec<CommandOutput>) -> Self {
            Self {
                outputs: RefCell::new(outputs),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn run(&self, _remote: &RemoteBox, command: &str) -> anyhow::Result<CommandOutput> {
            self.commands.borrow_mut().push(command.to_string());
            let mut outputs = self.outputs.borrow_mut();
            anyhow::ensure!(!outputs.is_empty(), "fake transport exhausted");
            Ok(outputs.remove(0))
        }

        fn push(
            &self,
            _remote: &RemoteBox,
            _local: &std::path::Path,
            _remote_path: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn pull(
            &self,
            _remote: &RemoteBox,
            _remote_path: &str,
            _local: &std::path::Path,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn remote() -> RemoteBox {
        RemoteBox {
            name: "devpod".to_string(),
            ssh: "ubuntu@devpod".to_string(),
            workdir: "/home/ubuntu/kz-fleet".to_string(),
            slots: 2,
            session_prefix: "kz-fleet".to_string(),
        }
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            exit_code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn all_green_doctor_passes() {
        let transport = FakeTransport::with_outputs(vec![
            ok(""),
            ok("kuzushi 0.24.0"),
            ok("52428800"), // 50 GiB in KiB
            ok("ok"),
        ]);

        let report = doctor(&transport, &remote()).unwrap();

        assert!(report.passed(), "{report:?}");
    }

    #[test]
    fn missing_engine_or_low_disk_fails_the_gate() {
        let transport = FakeTransport::with_outputs(vec![
            ok(""),
            ok(""),           // no version output → engine missing
            ok("1048576"),    // 1 GiB free
            ok("ok"),
        ]);

        let report = doctor(&transport, &remote()).unwrap();

        assert!(!report.passed());
        let failed: Vec<_> = report
            .checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| check.name.as_str())
            .collect();
        assert_eq!(failed, vec!["engine", "disk"]);
    }
}
