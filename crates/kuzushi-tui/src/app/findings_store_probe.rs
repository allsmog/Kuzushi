//! Idle-tick detection of findings written by another process.
//!
//! A headless `kuzushi run` (or any other writer) can commit findings to the
//! target's store while the shell sits idle. The workspace watcher ignores the
//! SQLite WAL side file, may still be registering on a large tree, or may be
//! unavailable altogether, so such a write could leave the shell's ledger
//! stale indefinitely. This probe stats the store's main and WAL files on the
//! existing idle tick, at most once per [`FINDINGS_STORE_PROBE_INTERVAL`], and
//! reloads findings only when that stat identity moved and the store's
//! projection watermark differs from the one the shell last read.

use super::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// Upper bound on how often the idle shell stats the findings store.
pub(crate) const FINDINGS_STORE_PROBE_INTERVAL: Duration = Duration::from_secs(2);

const FINDINGS_STORE_RELATIVE_PATH: &str = ".kuzushi/v3/index.sqlite3";
const FINDINGS_STORE_WAL_RELATIVE_PATH: &str = ".kuzushi/v3/index.sqlite3-wal";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreFileStamp {
    pub(crate) len: u64,
    pub(crate) modified: Option<SystemTime>,
}

/// Stat identity of one target's findings store. Committed writes land in
/// the WAL first and in the main file on checkpoint, so both are compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingsStoreStamp {
    pub(crate) target: PathBuf,
    pub(crate) main: Option<StoreFileStamp>,
    pub(crate) wal: Option<StoreFileStamp>,
}

impl FindingsStoreStamp {
    pub(crate) fn read(target: &Path) -> Self {
        Self {
            target: target.to_path_buf(),
            main: read_file_stamp(&target.join(FINDINGS_STORE_RELATIVE_PATH)),
            wal: read_file_stamp(&target.join(FINDINGS_STORE_WAL_RELATIVE_PATH)),
        }
    }
}

fn read_file_stamp(path: &Path) -> Option<StoreFileStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some(StoreFileStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

/// Probe cadence: never while local work runs (its own completion refreshes
/// findings), and never faster than the probe interval.
pub(crate) fn findings_store_probe_due(
    last_check: Option<Instant>,
    now: Instant,
    work_running: bool,
) -> bool {
    !work_running
        && last_check.is_none_or(|checked| {
            now.saturating_duration_since(checked) >= FINDINGS_STORE_PROBE_INTERVAL
        })
}

/// The first observation of a target is a baseline; afterwards any change of
/// the same target's stat identity is a candidate external write.
pub(crate) fn findings_store_stamp_changed(
    previous: Option<&FindingsStoreStamp>,
    current: &FindingsStoreStamp,
) -> bool {
    previous.is_some_and(|previous| previous.target == current.target && previous != current)
}

#[derive(Debug, Default)]
pub(crate) struct FindingsStoreProbe {
    last_check: Option<Instant>,
    last_stamp: Option<FindingsStoreStamp>,
}

impl FindingsStoreProbe {
    pub(crate) fn due(&self, now: Instant, work_running: bool) -> bool {
        findings_store_probe_due(self.last_check, now, work_running)
    }

    /// Record `stamp` as observed at `now`; true when it moved since the
    /// previous observation of the same target.
    pub(crate) fn observe(&mut self, now: Instant, stamp: FindingsStoreStamp) -> bool {
        let changed = findings_store_stamp_changed(self.last_stamp.as_ref(), &stamp);
        self.last_check = Some(now);
        self.last_stamp = Some(stamp);
        changed
    }
}

impl ShellApp {
    /// Reload findings when another process changed the target's store.
    /// Returns true when a reload ran.
    pub(crate) fn refresh_findings_after_external_store_write(&mut self, now: Instant) -> bool {
        let effects = self.external_findings_store_effects(now);
        let changed = !effects.is_empty();
        EffectRuntime::execute(self, effects);
        changed
    }

    fn external_findings_store_effects(&mut self, now: Instant) -> Vec<ShellEffect> {
        let work_running = self.has_local_running_work();
        if !self
            .runtime_state
            .findings_store_probe()
            .due(now, work_running)
        {
            return Vec::new();
        }
        let Some(target) = self.target_owned() else {
            return Vec::new();
        };
        let stamp = FindingsStoreStamp::read(&target);
        let moved = self
            .runtime_state
            .findings_store_probe_mut()
            .observe(now, stamp);
        if !moved || !self.findings_projection_refresh_needed(&target) {
            return Vec::new();
        }
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: self.active_findings_filter().clone(),
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, FindingStore, Severity, V2Config, WorkspaceTarget};

    fn stamp(target: &str, main_len: u64, wal_len: Option<u64>) -> FindingsStoreStamp {
        let file = |len| StoreFileStamp {
            len,
            modified: Some(SystemTime::UNIX_EPOCH),
        };
        FindingsStoreStamp {
            target: PathBuf::from(target),
            main: Some(file(main_len)),
            wal: wal_len.map(file),
        }
    }

    #[test]
    fn probe_is_due_only_when_idle_and_after_the_interval() {
        let now = Instant::now();
        assert!(findings_store_probe_due(None, now, false));
        assert!(!findings_store_probe_due(None, now, true));
        assert!(!findings_store_probe_due(Some(now), now, false));
        let later = now + FINDINGS_STORE_PROBE_INTERVAL;
        assert!(findings_store_probe_due(Some(now), later, false));
        assert!(!findings_store_probe_due(Some(now), later, true));
    }

    #[test]
    fn first_observation_is_a_baseline_and_later_moves_are_changes() {
        let base = stamp("/t", 10, Some(0));
        assert!(!findings_store_stamp_changed(None, &base));
        assert!(!findings_store_stamp_changed(Some(&base), &base.clone()));
        assert!(findings_store_stamp_changed(
            Some(&base),
            &stamp("/t", 10, Some(4096))
        ));
        assert!(findings_store_stamp_changed(
            Some(&base),
            &stamp("/t", 20, Some(0))
        ));
        assert!(findings_store_stamp_changed(
            Some(&base),
            &stamp("/t", 10, None)
        ));
    }

    #[test]
    fn switching_targets_rebaselines_instead_of_reloading() {
        assert!(!findings_store_stamp_changed(
            Some(&stamp("/a", 10, None)),
            &stamp("/b", 99, None)
        ));
    }

    fn store_with_one_finding() -> (tempfile::TempDir, WorkspaceTarget) {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("scan-1", workspace.root(), "completed")
            .unwrap();
        insert_finding(&store, "demo.first", 1);
        (temp, workspace)
    }

    fn insert_finding(store: &FindingStore, rule: &str, line: u32) {
        store
            .insert_finding(
                "scan-1",
                &Finding::new_semgrep(rule, "src/app.rs", line, None, Severity::High, rule),
            )
            .unwrap();
    }

    #[test]
    fn idle_probe_reloads_findings_committed_by_another_process() {
        let (_temp, workspace) = store_with_one_finding();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);
        let start = Instant::now();
        assert!(!app.refresh_findings_after_external_store_write(start));

        let external = FindingStore::open(workspace.findings_db_path()).unwrap();
        insert_finding(&external, "demo.second", 2);
        drop(external);

        let early = start + FINDINGS_STORE_PROBE_INTERVAL / 2;
        assert!(!app.refresh_findings_after_external_store_write(early));
        assert_eq!(app.findings().len(), 1);

        let due = start + FINDINGS_STORE_PROBE_INTERVAL;
        assert!(app.refresh_findings_after_external_store_write(due));
        assert_eq!(app.findings().len(), 2);

        let next = due + FINDINGS_STORE_PROBE_INTERVAL;
        assert!(!app.refresh_findings_after_external_store_write(next));
    }

    #[test]
    fn held_dispatcher_keeps_external_findings_refresh_live() {
        let (_temp, workspace) = store_with_one_finding();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.refresh_findings(false);
        let mut held = crate::app::owned_dispatcher_test_support::HeldDispatcher::hold(&mut app);
        let start = Instant::now();
        assert!(!held.refresh_findings_after_external_store_write(start));
        let external = FindingStore::open(workspace.findings_db_path()).unwrap();
        insert_finding(&external, "external.during.study", 2);
        drop(external);

        assert!(
            held.refresh_findings_after_external_store_write(start + FINDINGS_STORE_PROBE_INTERVAL)
        );
        assert_eq!(held.findings().len(), 2);
        assert!(held.has_running_work());
        assert!(!held.directory().join("dispatcher-stop.json").exists());
    }
}
