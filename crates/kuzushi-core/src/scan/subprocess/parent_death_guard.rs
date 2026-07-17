use anyhow::{Context, Result};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};

const GUARD_SCRIPT: &str = r#"
trap '' HUP INT TERM
while IFS= read -r _; do :; done
/bin/kill -KILL -- -"$$"
"#;

/// Owns the Unix process group that contains one scanner and all descendants.
///
/// The guard waits on a pipe whose writer exists only in the Kuzushi process.
/// If Kuzushi exits normally, cancellation kills the group and then closes the
/// pipe. If Kuzushi is killed abruptly, the kernel closes the pipe and the
/// guard kills its own process group, including the scanner.
#[derive(Debug)]
pub(in crate::scan) struct ParentDeathGuard {
    process: Child,
    keepalive: Option<ChildStdin>,
}

impl ParentDeathGuard {
    pub(super) fn spawn() -> Result<Self> {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", GUARD_SCRIPT, "kuzushi-scanner-guard"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut process = command
            .spawn()
            .context("start scanner parent-death guard")?;
        let keepalive = process
            .stdin
            .take()
            .context("open scanner parent-death guard lifeline")?;
        Ok(Self {
            process,
            keepalive: Some(keepalive),
        })
    }

    pub(super) fn process_group_id(&self) -> u32 {
        self.process.id()
    }

    pub(super) fn finish(&mut self) {
        self.keepalive.take();
        wait_for_guard(&mut self.process);
    }
}

impl Drop for ParentDeathGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

fn wait_for_guard(process: &mut Child) {
    match process.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(_) => return,
    }
    let _ = process.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_owns_a_distinct_process_group() {
        let mut guard = ParentDeathGuard::spawn().unwrap();
        let group = unsafe { libc::getpgid(guard.process.id() as libc::pid_t) };

        assert_eq!(group, guard.process.id() as libc::pid_t);

        guard.finish();
    }

    #[test]
    fn guard_uses_external_kill_for_process_group_syntax() {
        assert!(GUARD_SCRIPT.contains("/bin/kill -KILL --"));
    }
}
