use super::TerminalLoopWake;
use kuzushi_core::NestedProjectScopeTree;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

#[derive(Debug)]
pub(crate) struct ProjectScopeDiscoveryResult {
    pub(crate) root: PathBuf,
    pub(crate) tree: Result<NestedProjectScopeTree, String>,
}

#[derive(Debug)]
struct StampedProjectScopeDiscoveryResult {
    generation: u64,
    result: ProjectScopeDiscoveryResult,
}

#[derive(Debug)]
pub(crate) struct ProjectScopeDiscoveryRuntime {
    generation: u64,
    active_root: Option<PathBuf>,
    tx: Sender<StampedProjectScopeDiscoveryResult>,
    rx: Receiver<StampedProjectScopeDiscoveryResult>,
}

impl Default for ProjectScopeDiscoveryRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            generation: 0,
            active_root: None,
            tx,
            rx,
        }
    }
}

impl ProjectScopeDiscoveryRuntime {
    pub(crate) fn start(&mut self, root: PathBuf, wake: Option<TerminalLoopWake>) {
        self.generation = self.generation.wrapping_add(1);
        self.active_root = Some(root.clone());
        let generation = self.generation;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let tree = kuzushi_core::discover_and_save_nested_project_scopes(&root)
                .map_err(|error| error.to_string());
            let result = ProjectScopeDiscoveryResult { root, tree };
            let _ = tx.send(StampedProjectScopeDiscoveryResult { generation, result });
            if let Some(wake) = wake {
                wake.notify();
            }
        });
    }

    pub(crate) fn drain_current(&mut self) -> Vec<ProjectScopeDiscoveryResult> {
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

    fn is_current(&self, result: &StampedProjectScopeDiscoveryResult) -> bool {
        result.generation == self.generation
            && self.active_root.as_ref() == Some(&result.result.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn newer_target_ignores_an_older_generation() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut runtime = ProjectScopeDiscoveryRuntime::default();
        runtime.start(first.path().to_path_buf(), None);
        runtime.start(second.path().to_path_buf(), None);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut results = Vec::new();
        while results.is_empty() && Instant::now() < deadline {
            results.extend(runtime.drain_current());
            std::thread::yield_now();
        }

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].root, second.path());
        assert!(results[0].tree.is_ok());
    }
}
