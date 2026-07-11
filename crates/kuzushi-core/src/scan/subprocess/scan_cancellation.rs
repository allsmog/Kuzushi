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
        let managed = prepare_managed_child(child, process_group_id)?;
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

fn prepare_managed_child(child: Child, process_group_id: Option<u32>) -> Result<ManagedChild> {
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
        #[cfg(windows)]
        job_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

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
        configure_scanner_process_group(&mut command);
        let child = command.spawn().unwrap();
        let process_group_id = child_process_group_id(&child);

        let error = cancellation
            .register_child(child, process_group_id)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("cancelled before child process registration"),
            "{error}"
        );
    }
}

#[derive(Debug)]
pub struct RegisteredChild {
    pub(in crate::scan) id: u64,
    pub(in crate::scan) children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}
