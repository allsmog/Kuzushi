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

    pub(in crate::scan) fn register_child(
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
pub(in crate::scan) struct RegisteredChild {
    pub(in crate::scan) id: u64,
    pub(in crate::scan) children: Arc<Mutex<HashMap<u64, ManagedChild>>>,
}
