use super::{receive_result, RunItemWriter, WriterCommand};
use anyhow::{Context, Result};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

impl RunItemWriter {
    pub fn shutdown(&self) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(WriterCommand::Shutdown(sender))
            .context("run-item writer stopped")?;
        let settlement = receive_result(receiver.recv(), "run-item shutdown");
        let joins = self.join_delivery_workers();
        settlement?;
        joins
    }

    fn join_delivery_workers(&self) -> Result<()> {
        join_worker(&self.thread, "run-item writer")?;
        join_worker(&self.delivery_thread, "run-item delivery worker")?;
        join_worker(
            &self.range_delivery_thread,
            "run-item range delivery worker",
        )?;
        detach_worker(&self.derivative_delivery_thread);
        Ok(())
    }
}

fn detach_worker(worker: &Arc<Mutex<Option<JoinHandle<()>>>>) {
    let _ = worker
        .lock()
        .expect("worker thread lock poisoned")
        .take();
}

impl Drop for RunItemWriter {
    fn drop(&mut self) {
        let last_handle = Arc::strong_count(&self.thread) == 1;
        let worker_live = self
            .thread
            .lock()
            .expect("writer thread lock poisoned")
            .is_some();
        if last_handle && worker_live {
            let _ = self.shutdown();
        }
    }
}

fn join_worker(worker: &Arc<Mutex<Option<JoinHandle<()>>>>, label: &str) -> Result<()> {
    let Some(thread) = worker.lock().expect("worker thread lock poisoned").take() else {
        return Ok(());
    };
    thread
        .join()
        .map_err(|_| anyhow::anyhow!("{label} panicked"))
}
