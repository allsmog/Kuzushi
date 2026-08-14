#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use tokio::process::{Child, Command};

/// Owns a process group that cannot outlive the process holding this value.
///
/// Unix uses a lifeline pipe to a tiny guard process. The kernel closes the
/// pipe even when the owner receives `SIGKILL`, and the guard then kills its
/// process group. Windows uses a kill-on-close Job Object.
#[derive(Debug, Default)]
pub struct ParentDeathProcessGroup {
    #[cfg(unix)]
    guard: Option<UnixParentDeathGuard>,
    #[cfg(windows)]
    job_handle: Option<isize>,
}

impl ParentDeathProcessGroup {
    pub fn configure(command: &mut Command) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            let guard = UnixParentDeathGuard::spawn()?;
            let group_id = i32::try_from(guard.group_id())
                .context("MCP subprocess group id exceeds the platform pid range")?;
            command.as_std_mut().process_group(group_id);
            return Ok(Self { guard: Some(guard) });
        }

        #[cfg(not(unix))]
        {
            let _ = command;
            Ok(Self::default())
        }
    }

    pub fn attach_child(&mut self, child: &Child) -> Result<()> {
        #[cfg(windows)]
        {
            self.job_handle = Some(super::windows_job::create_kill_on_close_job(child)?);
        }
        #[cfg(not(windows))]
        let _ = child;
        Ok(())
    }

    pub fn kill(&self) {
        #[cfg(unix)]
        if let Some(guard) = self.guard.as_ref() {
            kill_process_group(guard.group_id());
        }
        #[cfg(windows)]
        super::windows_job::terminate_job(self.job_handle);
    }

    pub fn process_group_id(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            return self.guard.as_ref().map(UnixParentDeathGuard::group_id);
        }
        #[cfg(not(unix))]
        None
    }
}

#[cfg(windows)]
impl Drop for ParentDeathProcessGroup {
    fn drop(&mut self) {
        super::windows_job::close_job(self.job_handle.take());
    }
}

#[cfg(unix)]
const GUARD_SCRIPT: &str = r#"
trap '' HUP INT TERM
while IFS= read -r _; do :; done
/bin/kill -KILL -- -"$$"
"#;

#[cfg(unix)]
#[derive(Debug)]
struct UnixParentDeathGuard {
    process: std::process::Child,
    keepalive: Option<std::process::ChildStdin>,
}

#[cfg(unix)]
impl UnixParentDeathGuard {
    fn spawn() -> Result<Self> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", GUARD_SCRIPT, "kuzushi-mcp-child-guard"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut process = command
            .spawn()
            .context("start MCP subprocess parent-death guard")?;
        let keepalive = process
            .stdin
            .take()
            .context("open MCP subprocess parent-death lifeline")?;
        Ok(Self {
            process,
            keepalive: Some(keepalive),
        })
    }

    fn group_id(&self) -> u32 {
        self.process.id()
    }

    fn finish(&mut self) {
        self.keepalive.take();
        let _ = self.process.wait();
    }
}

#[cfg(unix)]
impl Drop for UnixParentDeathGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(unix)]
fn kill_process_group(group_id: u32) {
    // SAFETY: the guard created and owns this dedicated process group.
    unsafe {
        libc::killpg(group_id as libc::pid_t, libc::SIGKILL);
    }
}
