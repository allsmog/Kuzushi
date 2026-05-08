use super::prelude::*;
use super::*;

impl RegisteredChild {
    pub(in crate::scan) fn try_wait(&self) -> Result<Option<ExitStatus>> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        let Some(managed) = children.get_mut(&self.id) else {
            return Ok(None);
        };
        let status = managed.child.try_wait()?;
        if status.is_some() {
            children.remove(&self.id);
        }
        Ok(status)
    }

    pub(in crate::scan) fn kill_and_wait(&self) -> Result<()> {
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        if let Some(mut child) = children.remove(&self.id) {
            kill_managed_child(&mut child);
            let _ = child.child.wait();
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(in crate::scan) struct ManagedChild {
    pub(in crate::scan) child: Child,
    pub(in crate::scan) process_group_id: Option<u32>,
}

pub(in crate::scan) fn kill_managed_child(child: &mut ManagedChild) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = child.process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            return;
        }
    }

    let _ = child.child.kill();
}

pub(in crate::scan) fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

pub(in crate::scan) fn configure_scanner_process_group(command: &mut Command) {
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

pub(in crate::scan) const SCANNER_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TMPDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NO_COLOR",
    "TERM",
];

pub(in crate::scan) fn configure_scanner_subprocess_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in scrubbed_scanner_environment() {
        command.env(key, value);
    }
}

pub(in crate::scan) fn scrubbed_scanner_environment(
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    env::vars_os()
        .filter(|(key, _)| key.to_str().is_some_and(|key| is_safe_scanner_env_key(key)))
        .collect()
}
