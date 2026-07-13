use super::super::KwpError;
use super::journal::AuditIdentity;
use super::writer::KwpAuditWriter;
use super::AuditPaths;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

static AUDIT_WRITERS: OnceLock<Mutex<AuditWriterRegistry>> = OnceLock::new();

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct AuditWriterKey {
    target: PathBuf,
    run_id: String,
}

impl AuditWriterKey {
    pub(super) fn new(target: &Path, run_id: &str) -> Result<Self, KwpError> {
        Ok(Self {
            target: qualified_target(target)?,
            run_id: run_id.to_string(),
        })
    }
}

pub(super) fn acquire_writer(
    key: &AuditWriterKey,
    paths: AuditPaths,
) -> Result<Arc<Mutex<KwpAuditWriter>>, KwpError> {
    audit_writer_registry()
        .lock()
        .map_err(|_| poisoned_registry())
        .map(|mut registry| registry.acquire(key, paths))
}

pub(super) fn release_writer(key: &AuditWriterKey, writer: &Arc<Mutex<KwpAuditWriter>>) {
    if let Ok(mut registry) = audit_writer_registry().lock() {
        registry.release(key, writer);
    }
}

#[derive(Default)]
struct AuditWriterRegistry {
    writers: HashMap<AuditWriterKey, Weak<Mutex<KwpAuditWriter>>>,
}

impl AuditWriterRegistry {
    fn acquire(&mut self, key: &AuditWriterKey, paths: AuditPaths) -> Arc<Mutex<KwpAuditWriter>> {
        self.remove_abandoned();
        if let Some(writer) = self.writers.get(key).and_then(Weak::upgrade) {
            return writer;
        }
        let identity = AuditIdentity::new(&key.target, &key.run_id);
        let writer = Arc::new(Mutex::new(KwpAuditWriter::new(identity, paths)));
        self.writers.insert(key.clone(), Arc::downgrade(&writer));
        writer
    }

    fn release(&mut self, key: &AuditWriterKey, writer: &Arc<Mutex<KwpAuditWriter>>) {
        if Arc::strong_count(writer) == 1
            && self
                .writers
                .get(key)
                .is_some_and(|registered| registered.ptr_eq(&Arc::downgrade(writer)))
        {
            self.writers.remove(key);
        }
        self.remove_abandoned();
    }

    fn remove_abandoned(&mut self) {
        self.writers.retain(|_, writer| writer.strong_count() > 0);
    }
}

fn qualified_target(target: &Path) -> Result<PathBuf, KwpError> {
    fs::canonicalize(target).map_err(|error| {
        KwpError::Internal(format!(
            "could not qualify KWP audit target {}: {error}",
            target.display()
        ))
    })
}

fn audit_writer_registry() -> &'static Mutex<AuditWriterRegistry> {
    AUDIT_WRITERS.get_or_init(|| Mutex::new(AuditWriterRegistry::default()))
}

fn poisoned_registry() -> KwpError {
    KwpError::Internal("KWP audit writer registry was poisoned".to_string())
}
