use std::collections::HashMap;
use std::env;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct ScanCancellation {
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    next_child_id: Arc<AtomicU64>,
    children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}

impl Default for ScanCancellation {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            next_child_id: Arc::new(AtomicU64::new(1)),
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ScanCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        // Cancel implies resume so any wait_if_paused() loops can see the cancel flag.
        self.paused.store(false, Ordering::SeqCst);
        if let Ok(mut children) = self.children.lock() {
            for child in children.values_mut() {
                kill_managed_child(child);
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn pause(&self) {
        if !self.cancelled.load(Ordering::SeqCst) {
            self.paused.store(true, Ordering::SeqCst);
        }
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Block the current thread until either resume() or cancel() is called.
    /// Returns immediately if not paused.
    pub fn wait_if_paused(&self) {
        while self.paused.load(Ordering::SeqCst) && !self.cancelled.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    pub(super) fn register_child(
        &self,
        child: Child,
        process_group_id: Option<u32>,
    ) -> Result<RegisteredChild> {
        let id = self.next_child_id.fetch_add(1, Ordering::SeqCst);
        let mut children = self
            .children
            .lock()
            .map_err(|_| anyhow::anyhow!("scan cancellation registry was poisoned"))?;
        children.insert(
            id,
            ManagedChild {
                child,
                process_group_id,
            },
        );
        Ok(RegisteredChild {
            id,
            children: Arc::clone(&self.children),
        })
    }
}

#[derive(Debug)]
pub(super) struct RegisteredChild {
    id: u64,
    children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}

impl RegisteredChild {
    pub(super) fn try_wait(&self) -> Result<Option<ExitStatus>> {
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

    pub(super) fn kill_and_wait(&self) -> Result<()> {
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
struct ManagedChild {
    child: Child,
    process_group_id: Option<u32>,
}

fn kill_managed_child(child: &mut ManagedChild) {
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

pub(super) fn child_process_group_id(child: &Child) -> Option<u32> {
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

pub(super) fn configure_scanner_process_group(command: &mut Command) {
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

const SCANNER_ENV_ALLOWLIST: &[&str] = &[
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

pub(super) fn configure_scanner_subprocess_env(command: &mut Command) {
    command.env_clear();
    for (key, value) in scrubbed_scanner_environment() {
        command.env(key, value);
    }
}

fn scrubbed_scanner_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    env::vars_os()
        .filter(|(key, _)| key.to_str().is_some_and(|key| is_safe_scanner_env_key(key)))
        .collect()
}

pub(crate) fn is_safe_scanner_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if is_credential_env_key(&upper) {
        return false;
    }

    SCANNER_ENV_ALLOWLIST
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(key))
        || upper.starts_with("LC_")
}

fn is_credential_env_key(upper_key: &str) -> bool {
    const SENSITIVE_EXACT: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "DATABASE_URL",
        "DB_URL",
    ];
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "CONNECTION_STRING",
        "COOKIE",
        "SESSION",
    ];

    SENSITIVE_EXACT.contains(&upper_key)
        || SENSITIVE_FRAGMENTS
            .iter()
            .any(|fragment| upper_key.contains(fragment))
}

#[derive(Debug)]
pub(super) struct ProcessOutput {
    pub(super) stdout: Vec<u8>,
}

pub(super) fn read_pipe(mut pipe: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    pipe.read_to_end(&mut output)?;
    Ok(output)
}
