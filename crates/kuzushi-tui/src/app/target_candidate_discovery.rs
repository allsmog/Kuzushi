use super::{discover_target_candidates, TargetCandidate, TerminalLoopWake};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

#[derive(Debug)]
pub(crate) struct TargetCandidateDiscoveryResult {
    pub(crate) cwd: PathBuf,
    pub(crate) candidates: Vec<TargetCandidate>,
}

#[derive(Debug)]
struct StampedTargetCandidateDiscoveryResult {
    generation: u64,
    result: TargetCandidateDiscoveryResult,
}

#[derive(Debug)]
pub(crate) struct TargetCandidateDiscoveryRuntime {
    generation: u64,
    active_cwd: Option<PathBuf>,
    tx: Sender<StampedTargetCandidateDiscoveryResult>,
    rx: Receiver<StampedTargetCandidateDiscoveryResult>,
}

impl Default for TargetCandidateDiscoveryRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            generation: 0,
            active_cwd: None,
            tx,
            rx,
        }
    }
}

impl TargetCandidateDiscoveryRuntime {
    pub(crate) fn start(&mut self, cwd: PathBuf, wake: Option<TerminalLoopWake>) {
        self.generation = self.generation.wrapping_add(1);
        self.active_cwd = Some(cwd.clone());
        let generation = self.generation;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let candidates = discover_target_candidates(&cwd);
            let result = TargetCandidateDiscoveryResult { cwd, candidates };
            let _ = tx.send(StampedTargetCandidateDiscoveryResult { generation, result });
            if let Some(wake) = wake {
                wake.notify();
            }
        });
    }

    pub(crate) fn drain_current(&mut self) -> Vec<TargetCandidateDiscoveryResult> {
        let mut current = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(stamped) if self.is_current(&stamped) => current.push(stamped.result),
                Ok(_) => {}
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        current
    }

    fn is_current(&self, result: &StampedTargetCandidateDiscoveryResult) -> bool {
        result.generation == self.generation && self.active_cwd.as_ref() == Some(&result.result.cwd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn newer_discovery_generation_discards_older_results() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut runtime = TargetCandidateDiscoveryRuntime::default();
        runtime.start(first.path().to_path_buf(), None);
        runtime.start(second.path().to_path_buf(), None);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut results = Vec::new();
        while results.is_empty() && Instant::now() < deadline {
            results.extend(runtime.drain_current());
            std::thread::yield_now();
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cwd, second.path());
        assert_eq!(results[0].candidates[0].path, second.path());
    }
}
