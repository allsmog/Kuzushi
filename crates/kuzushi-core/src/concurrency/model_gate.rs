use super::*;

impl ModelGate {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ModelGateInner {
                semaphores: Mutex::new(BTreeMap::new()),
                overrides: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// Install a per-model cap from configuration. Re-calling with a new
    /// value replaces the existing semaphore — outstanding permits are
    /// honoured but new acquisitions go through the fresh semaphore.
    pub fn set_cap(&self, model: &str, cap: usize) {
        self.inner
            .overrides
            .lock()
            .expect("overrides poisoned")
            .insert(model.to_string(), cap.max(1));
        // Force re-creation on next acquire.
        self.inner
            .semaphores
            .lock()
            .expect("semaphores poisoned")
            .remove(model);
    }

    /// Configured cap for `model`, falling back to the default heuristic.
    pub fn cap_for(&self, model: &str) -> usize {
        if let Some(&cap) = self
            .inner
            .overrides
            .lock()
            .expect("overrides poisoned")
            .get(model)
        {
            return cap;
        }
        default_concurrency_for(model)
    }

    /// Acquire a permit for `model` at `priority`. The future resolves
    /// when the underlying semaphore has capacity AND no higher-priority
    /// waiter is queued ahead. Returns a [`PriorityPermit`] that releases
    /// on drop and wakes the next queue head.
    pub async fn acquire(&self, model: &str, priority: Priority) -> PriorityPermit {
        let slot = self.slot(model);
        let notify = Arc::new(Notify::new());

        {
            let mut queues = slot.queues.lock().expect("queues poisoned");
            queues[priority.band()].push_back(Arc::clone(&notify));
        }

        loop {
            let head = queue_head(&slot.queues.lock().expect("queues poisoned"));
            let is_head = head
                .as_ref()
                .map(|h| Arc::ptr_eq(h, &notify))
                .unwrap_or(false);

            if !is_head {
                notify.notified().await;
                continue;
            }

            match Arc::clone(&slot.sem).try_acquire_owned() {
                Ok(permit) => {
                    {
                        let mut queues = slot.queues.lock().expect("queues poisoned");
                        queues[priority.band()].pop_front();
                    }
                    self.notify_next_head(&slot);
                    return PriorityPermit {
                        permit: Some(permit),
                        slot,
                        gate: self.clone(),
                    };
                }
                Err(_) => {
                    slot.permit_released.notified().await;
                }
            }
        }
    }

    pub(crate) fn slot(&self, model: &str) -> ModelSlot {
        let mut semaphores = self.inner.semaphores.lock().expect("semaphores poisoned");
        if let Some(slot) = semaphores.get(model) {
            return slot.clone();
        }
        let cap = self.cap_for(model);
        let slot = ModelSlot {
            sem: Arc::new(Semaphore::new(cap)),
            queues: Arc::new(Mutex::new([
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ])),
            permit_released: Arc::new(Notify::new()),
        };
        let cloned = slot.clone();
        semaphores.insert(model.to_string(), slot);
        cloned
    }

    pub(crate) fn notify_next_head(&self, slot: &ModelSlot) {
        let queues = slot.queues.lock().expect("queues poisoned");
        if let Some(head) = queue_head(&queues) {
            head.notify_one();
        }
    }
}
