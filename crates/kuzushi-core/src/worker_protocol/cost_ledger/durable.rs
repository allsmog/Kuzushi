use super::{InvocationId, KwpError, LedgerCostReport, RunId};
use crate::file_lock::ExclusiveFileLock;
use std::fs;
use std::path::{Path, PathBuf};

mod state;

use state::{validate_finite_cost, validate_invocation_id, DurableLedgerState, LedgerIdentity};

const LEDGER_FILE: &str = ".kwp-cost-ledger.json";
const LEDGER_LOCK_FILE: &str = ".kwp-cost-ledger.lock";
const MAX_LEDGER_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(super) struct DurableCostStore {
    identity: LedgerIdentity,
    ledger_path: PathBuf,
    lock_path: PathBuf,
}

impl DurableCostStore {
    pub(super) fn open(target: &Path, run_id: &RunId) -> Result<Self, KwpError> {
        let target = qualify_target(target)?;
        prepare_run_directory(&target, run_id)?;
        let store = Self {
            identity: LedgerIdentity::new(&target, run_id),
            ledger_path: ledger_path(&target, run_id, LEDGER_FILE)?,
            lock_path: ledger_path(&target, run_id, LEDGER_LOCK_FILE)?,
        };
        store.initialize(&target)?;
        Ok(store)
    }

    pub(super) fn reserve(
        &self,
        invocation_id: &InvocationId,
        invocation_limit: f64,
        run_limit: f64,
    ) -> Result<DurableCostReservation, KwpError> {
        validate_invocation_id(&invocation_id.0)?;
        let (reservation_id, limit) =
            self.update(|ledger| ledger.reserve(invocation_id, invocation_limit, run_limit))?;
        Ok(DurableCostReservation {
            store: self.clone(),
            reservation_id,
            limit,
        })
    }

    pub(super) fn invocation_cost_report(
        &self,
        invocation_id: &InvocationId,
    ) -> Result<LedgerCostReport, KwpError> {
        self.read(|ledger| ledger.invocation_cost_report(&invocation_id.0))
    }

    pub(super) fn run_cost_report(&self) -> Result<LedgerCostReport, KwpError> {
        self.read(DurableLedgerState::run_cost_report)
    }

    fn initialize(&self, target: &Path) -> Result<(), KwpError> {
        let _guard = self.acquire_lock()?;
        let canonical_cost = canonical_run_cost(target, &self.identity.run_id)?;
        if path_exists(&self.ledger_path)? {
            let mut ledger = self.load_state()?;
            if ledger.reconcile_canonical_cost(canonical_cost)? {
                self.write_state(&ledger)?;
            }
            Ok(())
        } else {
            self.write_state(&DurableLedgerState::new(&self.identity, canonical_cost))
        }
    }

    fn read<T>(
        &self,
        operation: impl FnOnce(&DurableLedgerState) -> Result<T, KwpError>,
    ) -> Result<T, KwpError> {
        let _guard = self.acquire_lock()?;
        let ledger = self.load_state()?;
        operation(&ledger)
    }

    fn update<T>(
        &self,
        operation: impl FnOnce(&mut DurableLedgerState) -> Result<T, KwpError>,
    ) -> Result<T, KwpError> {
        let _guard = self.acquire_lock()?;
        let mut ledger = self.load_state()?;
        let result = operation(&mut ledger)?;
        self.write_state(&ledger)?;
        Ok(result)
    }

    fn acquire_lock(&self) -> Result<ExclusiveFileLock, KwpError> {
        ExclusiveFileLock::acquire(&self.lock_path).map_err(|error| {
            KwpError::Internal(format!(
                "could not lock KWP cost ledger {}: {error}",
                self.lock_path.display()
            ))
        })
    }

    fn load_state(&self) -> Result<DurableLedgerState, KwpError> {
        let body = crate::bounded_file::read_utf8_text(&self.ledger_path, MAX_LEDGER_BYTES)
            .map_err(|error| ledger_read_error(&self.ledger_path, error))?;
        let ledger: DurableLedgerState = serde_json::from_str(&body).map_err(|error| {
            KwpError::Internal(format!(
                "could not parse KWP cost ledger {}: {error}",
                self.ledger_path.display()
            ))
        })?;
        ledger.validate(&self.identity)?;
        Ok(ledger)
    }

    fn write_state(&self, ledger: &DurableLedgerState) -> Result<(), KwpError> {
        ledger.validate(&self.identity)?;
        let mut body = serde_json::to_vec_pretty(ledger)
            .map_err(|error| KwpError::Internal(error.to_string()))?;
        body.push(b'\n');
        if body.len() > MAX_LEDGER_BYTES {
            return Err(KwpError::Internal(
                "KWP cost ledger exceeds its bounded size".to_string(),
            ));
        }
        crate::fs_atomic::write_atomic_bytes(&self.ledger_path, &body).map_err(|error| {
            KwpError::Internal(format!(
                "could not persist KWP cost ledger {}: {error}",
                self.ledger_path.display()
            ))
        })
    }

    fn commit(&self, reservation_id: &str, actual_cost: f64, limit: f64) -> Result<bool, KwpError> {
        self.update(|ledger| ledger.commit(reservation_id, actual_cost, limit))
    }

    fn rollback(&self, reservation_id: &str) -> Result<(), KwpError> {
        self.update(|ledger| {
            ledger.rollback(reservation_id);
            Ok(())
        })
    }
}

pub(super) struct DurableCostReservation {
    store: DurableCostStore,
    reservation_id: String,
    limit: f64,
}

impl DurableCostReservation {
    pub(super) fn commit(&self, actual_cost: f64) -> Result<bool, KwpError> {
        self.store
            .commit(&self.reservation_id, actual_cost, self.limit)
    }

    pub(super) fn rollback(&self) {
        // A failed rollback leaves the reservation durably charged. This is
        // intentionally fail-closed when storage state is uncertain.
        let _ = self.store.rollback(&self.reservation_id);
    }
}

fn canonical_run_cost(target: &Path, run_id: &str) -> Result<f64, KwpError> {
    let path = crate::run_artifacts::checked_run_artifact_path(target, run_id, "run.json")
        .map_err(|error| ledger_path_error("run summary", error))?;
    if !path_exists(&path)? {
        return Ok(0.0);
    }
    let body = crate::bounded_file::read_utf8_text(&path, MAX_LEDGER_BYTES)
        .map_err(|error| ledger_read_error(&path, error))?;
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| invalid_ledger(&format!("run summary is invalid: {error}")))?;
    validate_summary_run_id(&value, run_id)?;
    match value.get("costUsd") {
        None | Some(serde_json::Value::Null) => Ok(0.0),
        Some(value) => value
            .as_f64()
            .ok_or_else(|| invalid_ledger("run summary cost is invalid"))
            .and_then(|cost| {
                validate_finite_cost(cost, "run summary cost")?;
                Ok(cost)
            }),
    }
}

fn validate_summary_run_id(value: &serde_json::Value, run_id: &str) -> Result<(), KwpError> {
    match value.get("runId").and_then(serde_json::Value::as_str) {
        Some(actual) if actual == run_id => Ok(()),
        Some(_) => Err(invalid_ledger("run summary binding mismatch")),
        None => Err(invalid_ledger("run summary runId is missing")),
    }
}

fn qualify_target(target: &Path) -> Result<PathBuf, KwpError> {
    fs::canonicalize(target).map_err(|error| {
        KwpError::Internal(format!(
            "could not qualify KWP cost target {}: {error}",
            target.display()
        ))
    })
}

fn prepare_run_directory(target: &Path, run_id: &RunId) -> Result<(), KwpError> {
    crate::run_artifacts::ensure_run_artifact_parent(target, &run_id.0, LEDGER_FILE)
        .map(|_| ())
        .map_err(|error| ledger_path_error("receipt", error))
}

fn ledger_path(target: &Path, run_id: &RunId, leaf: &str) -> Result<PathBuf, KwpError> {
    crate::run_artifacts::checked_run_artifact_path(target, &run_id.0, leaf)
        .map_err(|error| ledger_path_error(leaf, error))
}

fn path_exists(path: &Path) -> Result<bool, KwpError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(invalid_ledger("receipt is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ledger_read_error(path, error)),
    }
}

fn target_binding(target: &Path) -> String {
    let identity = target_identity_bytes(target);
    super::super::sha256_digest(&identity).0
}

#[cfg(unix)]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    target.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    encode_wide_identity(target.as_os_str().encode_wide())
}

#[cfg(not(any(unix, windows)))]
fn target_identity_bytes(target: &Path) -> Vec<u8> {
    target.as_os_str().as_encoded_bytes().to_vec()
}

#[cfg(any(windows, test))]
fn encode_wide_identity(wide: impl IntoIterator<Item = u16>) -> Vec<u8> {
    wide.into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

fn ledger_path_error(subject: &str, error: anyhow::Error) -> KwpError {
    KwpError::Internal(format!("could not resolve KWP cost {subject}: {error}"))
}

fn ledger_read_error(path: &Path, error: std::io::Error) -> KwpError {
    KwpError::Internal(format!(
        "could not read KWP cost ledger {}: {error}",
        path.display()
    ))
}

fn invalid_ledger(reason: &str) -> KwpError {
    KwpError::Internal(format!("invalid KWP cost ledger: {reason}"))
}

#[cfg(test)]
pub(super) fn receipt_path(target: &Path, run_id: &RunId) -> PathBuf {
    crate::run_artifacts::run_artifact_path(target, &run_id.0, LEDGER_FILE)
}

#[cfg(test)]
mod tests {
    use super::encode_wide_identity;

    #[test]
    fn windows_wide_identity_preserves_unpaired_surrogates() {
        let left = encode_wide_identity([0x0061, 0xd800, 0x0062]);
        let right = encode_wide_identity([0x0061, 0xd801, 0x0062]);

        assert_ne!(left, right);
        assert_eq!(left, vec![0x61, 0, 0, 0xd8, 0x62, 0]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_target_identity_is_lossless_for_non_unicode_paths() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let left = std::path::PathBuf::from(OsString::from_wide(&[0xd800]));
        let right = std::path::PathBuf::from(OsString::from_wide(&[0xd801]));

        assert_ne!(
            super::target_identity_bytes(&left),
            super::target_identity_bytes(&right)
        );
    }
}
