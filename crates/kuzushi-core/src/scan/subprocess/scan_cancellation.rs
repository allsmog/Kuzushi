use super::*;

const CANCELLATION_ACTIVE: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CancellationDisposition {
    Canceled = 1,
    Interrupted = 2,
}

#[derive(Debug, Clone)]
pub struct ScanCancellation {
    pub(in crate::scan) disposition: Arc<AtomicU8>,
    pub(in crate::scan) paused: Arc<AtomicBool>,
    pub(in crate::scan) next_child_id: Arc<AtomicU64>,
    pub(in crate::scan) children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}

impl Default for ScanCancellation {
    fn default() -> Self {
        Self {
            disposition: Arc::new(AtomicU8::new(CANCELLATION_ACTIVE)),
            paused: Arc::new(AtomicBool::new(false)),
            next_child_id: Arc::new(AtomicU64::new(1)),
            children: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ScanCancellation {
    pub fn cancel(&self) {
        self.request(CancellationDisposition::Canceled);
    }

    pub fn interrupt(&self) {
        self.request(CancellationDisposition::Interrupted);
    }

    pub fn disposition(&self) -> Option<CancellationDisposition> {
        match self.disposition.load(Ordering::SeqCst) {
            value if value == CancellationDisposition::Canceled as u8 => {
                Some(CancellationDisposition::Canceled)
            }
            value if value == CancellationDisposition::Interrupted as u8 => {
                Some(CancellationDisposition::Interrupted)
            }
            _ => None,
        }
    }

    fn request(&self, disposition: CancellationDisposition) {
        let _ = self.disposition.compare_exchange(
            CANCELLATION_ACTIVE,
            disposition as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        // Cancellation implies resume so paused loops can observe the terminal disposition.
        self.paused.store(false, Ordering::SeqCst);
        if let Ok(mut children) = self.children.lock() {
            for child in children.values_mut() {
                kill_managed_child(child);
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.disposition().is_some()
    }

    pub fn pause(&self) {
        if !self.is_cancelled() {
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
        while self.paused.load(Ordering::SeqCst) && !self.is_cancelled() {
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

    /// Register a child configured by [`PreparedProcessGroup`], retaining its
    /// parent-death lifeline until the child and all descendants are reaped.
    pub fn register_prepared_child(
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
    fn first_cancellation_disposition_wins() {
        let operator_cancel = ScanCancellation::default();
        operator_cancel.cancel();
        operator_cancel.interrupt();
        assert_eq!(
            operator_cancel.disposition(),
            Some(CancellationDisposition::Canceled)
        );

        let watchdog_interrupt = ScanCancellation::default();
        watchdog_interrupt.interrupt();
        watchdog_interrupt.cancel();
        assert_eq!(
            watchdog_interrupt.disposition(),
            Some(CancellationDisposition::Interrupted)
        );
    }

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

        let stopped = wait_for_process_group_exit(&processes);
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
                if let Some(processes) = parse_owner_processes(&value) {
                    return processes;
                }
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
    fn parse_owner_processes(value: &str) -> Option<OwnerProcesses> {
        let mut values = value.split_whitespace();
        Some(OwnerProcesses {
            process_group_id: values.next()?.parse().ok()?,
            scanner_pid: values.next()?.parse().ok()?,
            descendant_pid: values.next()?.parse().ok()?,
        })
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
    fn wait_for_process_group_exit(processes: &OwnerProcesses) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if !tracked_process_group_is_active(processes) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[cfg(unix)]
    fn tracked_process_group_is_active(processes: &OwnerProcesses) -> bool {
        if !process_group_is_alive(processes.process_group_id) {
            return false;
        }
        #[cfg(target_os = "linux")]
        return [
            processes.process_group_id,
            processes.scanner_pid,
            processes.descendant_pid,
        ]
        .into_iter()
        .any(|pid| active_linux_group_member(pid, processes.process_group_id));
        #[cfg(not(target_os = "linux"))]
        true
    }

    #[cfg(target_os = "linux")]
    fn active_linux_group_member(process_id: u32, process_group_id: u32) -> bool {
        process_group_of(process_id) == Some(process_group_id) && !linux_process_is_dead(process_id)
    }

    #[cfg(target_os = "linux")]
    fn linux_process_is_dead(process_id: u32) -> bool {
        let stat = match std::fs::read_to_string(format!("/proc/{process_id}/stat")) {
            Ok(stat) => stat,
            Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
        };
        matches!(
            stat.rsplit_once(") ")
                .and_then(|(_, fields)| fields.chars().next()),
            Some('Z' | 'X')
        )
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
