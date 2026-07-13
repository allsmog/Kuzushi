use super::*;

#[derive(Debug, Clone)]
pub struct ScanCancellation {
    pub(in crate::scan) cancelled: Arc<AtomicBool>,
    pub(in crate::scan) paused: Arc<AtomicBool>,
    pub(in crate::scan) next_child_id: Arc<AtomicU64>,
    pub(in crate::scan) children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
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

    pub fn register_child(
        &self,
        child: Child,
        process_group_id: Option<u32>,
    ) -> Result<RegisteredChild> {
        let managed = prepare_managed_child(
            child,
            process_group_id,
            #[cfg(unix)]
            None,
        )?;
        self.insert_managed_child(managed)
    }

    pub(crate) fn register_prepared_child(
        &self,
        child: Child,
        process_group: PreparedProcessGroup,
    ) -> Result<RegisteredChild> {
        #[cfg(unix)]
        let (process_group_id, parent_death_guard) = process_group.into_parts();
        #[cfg(not(unix))]
        let process_group_id = process_group.into_process_group_id();
        let managed = prepare_managed_child(
            child,
            process_group_id,
            #[cfg(unix)]
            parent_death_guard,
        )?;
        self.insert_managed_child(managed)
    }

    fn insert_managed_child(&self, mut managed: ManagedChild) -> Result<RegisteredChild> {
        let id = self.next_child_id.fetch_add(1, Ordering::SeqCst);
        let mut children = match self.children.lock() {
            Ok(children) => children,
            Err(_) => {
                kill_managed_child(&mut managed);
                let _ = managed.child.wait();
                anyhow::bail!("scan cancellation registry was poisoned");
            }
        };
        if self.is_cancelled() {
            drop(children);
            kill_managed_child(&mut managed);
            let _ = managed.child.wait();
            anyhow::bail!("operation was cancelled before child process registration");
        }
        children.insert(id, managed);
        Ok(RegisteredChild {
            id,
            children: Arc::clone(&self.children),
        })
    }
}

fn prepare_managed_child(
    child: Child,
    process_group_id: Option<u32>,
    #[cfg(unix)] parent_death_guard: Option<ParentDeathGuard>,
) -> Result<ManagedChild> {
    #[cfg(windows)]
    let mut child = child;
    #[cfg(windows)]
    let job_handle = match create_kill_on_close_job(&child) {
        Ok(job_handle) => Some(job_handle),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    Ok(ManagedChild {
        child,
        process_group_id,
        #[cfg(unix)]
        parent_death_guard,
        #[cfg(windows)]
        job_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[cfg(unix)]
    const OWNER_TEST_PATH_ENV: &str = "KUZUSHI_SCANNER_OWNER_TEST_PATH";

    #[test]
    fn child_registered_after_cancellation_is_killed_and_rejected() {
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let mut command = Command::new("node");
        command
            .args(["-e", "setTimeout(() => {}, 60_000)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let process_group = PreparedProcessGroup::configure(&mut command).unwrap();
        let child = command.spawn().unwrap();

        let error = cancellation
            .register_prepared_child(child, process_group)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("cancelled before child process registration"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scanner_group_dies_when_its_owner_is_sigkilled() {
        if let Some(owner_state_path) = std::env::var_os(OWNER_TEST_PATH_ENV) {
            run_scanner_owner_process(&owner_state_path);
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let owner_state_path = temp.path().join("scanner-owner-state");
        let mut owner = Command::new(std::env::current_exe().unwrap())
            .arg("scanner_group_dies_when_its_owner_is_sigkilled")
            .env(OWNER_TEST_PATH_ENV, &owner_state_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let processes = wait_for_owner_processes(&mut owner, &owner_state_path);

        assert_eq!(
            process_group_of(processes.scanner_pid),
            Some(processes.process_group_id)
        );
        assert_eq!(
            process_group_of(processes.descendant_pid),
            Some(processes.process_group_id)
        );
        unsafe {
            libc::kill(owner.id() as libc::pid_t, libc::SIGKILL);
        }
        owner.wait().unwrap();

        let stopped = wait_for_process_group_exit(processes.process_group_id);
        if !stopped {
            unsafe {
                libc::killpg(processes.process_group_id as libc::pid_t, libc::SIGKILL);
            }
        }
        assert!(
            stopped,
            "scanner process group {} survived",
            processes.process_group_id
        );
    }

    #[cfg(unix)]
    fn run_scanner_owner_process(owner_state_path: &std::ffi::OsStr) {
        let owner_state_path = std::path::Path::new(owner_state_path);
        let descendant_path = owner_state_path.with_extension("descendant");
        let cancellation = ScanCancellation::default();
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 60 & printf '%s' \"$!\" > \"$1\"; wait",
                "scanner-owner-test",
            ])
            .arg(&descendant_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let process_group = PreparedProcessGroup::configure(&mut command).unwrap();
        let process_group_id = process_group.process_group_id().unwrap();
        let child = command.spawn().unwrap();
        let scanner_pid = child.id();
        let _registered = cancellation
            .register_prepared_child(child, process_group)
            .unwrap();
        let descendant_pid = wait_for_descendant_pid(&descendant_path);
        std::fs::write(
            owner_state_path,
            format!("{process_group_id} {scanner_pid} {descendant_pid}"),
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }

    #[cfg(unix)]
    struct OwnerProcesses {
        process_group_id: u32,
        scanner_pid: u32,
        descendant_pid: u32,
    }

    #[cfg(unix)]
    fn wait_for_owner_processes(owner: &mut Child, path: &std::path::Path) -> OwnerProcesses {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(value) = std::fs::read_to_string(path) {
                let values = value
                    .split_whitespace()
                    .map(|value| value.parse::<u32>().unwrap())
                    .collect::<Vec<_>>();
                return OwnerProcesses {
                    process_group_id: values[0],
                    scanner_pid: values[1],
                    descendant_pid: values[2],
                };
            }
            assert!(
                owner.try_wait().unwrap().is_none(),
                "owner helper exited early"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = owner.kill();
        let _ = owner.wait();
        panic!("owner helper did not publish its scanner process group");
    }

    #[cfg(unix)]
    fn wait_for_descendant_pid(path: &std::path::Path) -> u32 {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(value) = std::fs::read_to_string(path) {
                return value.trim().parse().unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("scanner helper did not publish its descendant pid");
    }

    #[cfg(unix)]
    fn wait_for_process_group_exit(process_group_id: u32) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !process_group_is_alive(process_group_id) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[cfg(unix)]
    fn process_group_is_alive(process_group_id: u32) -> bool {
        let result = unsafe { libc::killpg(process_group_id as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[cfg(unix)]
    fn process_group_of(process_id: u32) -> Option<u32> {
        let group = unsafe { libc::getpgid(process_id as libc::pid_t) };
        (group >= 0).then_some(group as u32)
    }
}

#[derive(Debug)]
pub struct RegisteredChild {
    pub(in crate::scan) id: u64,
    pub(in crate::scan) children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}
