//! One shared allowance for pack documents and iterative directory inspection.
mod walk;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy)]
pub(super) struct LintLimits {
    pub(super) entries: usize,
    pub(super) per_file: usize,
    pub(super) bytes: usize,
}
impl Default for LintLimits {
    fn default() -> Self {
        Self {
            entries: 100_000,
            per_file: 8 * 1024 * 1024,
            bytes: 64 * 1024 * 1024,
        }
    }
}
impl LintLimits {
    pub(super) fn parse(input: &Value) -> Result<Self> {
        let defaults = Self::default();
        Ok(Self {
            entries: limit(input, "maxWalkEntries", defaults.entries, 100_000)?,
            per_file: limit(
                input,
                "maxBytesPerFile",
                defaults.per_file,
                defaults.per_file,
            )?,
            bytes: limit(input, "maxReadBytes", defaults.bytes, 512 * 1024 * 1024)?,
        })
    }
}
fn limit(input: &Value, key: &str, default: usize, ceiling: usize) -> Result<usize> {
    let value = input
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .with_context(|| format!("{key} must be a positive integer"))
        })
        .transpose()?
        .unwrap_or(default as u64);
    anyhow::ensure!(
        value > 0 && value <= ceiling as u64,
        "{key} must be between 1 and {ceiling}"
    );
    Ok(value as usize)
}
#[derive(Default)]
struct Usage {
    entries: usize,
    captured: usize,
    reserved: usize,
    omissions: usize,
    hidden: usize,
    canceled: bool,
    reasons: BTreeSet<String>,
}
pub(super) struct LintResources<'a> {
    pub(super) root: PathBuf,
    requested_root: PathBuf,
    limits: LintLimits,
    usage: RefCell<Usage>,
    canceled: &'a dyn Fn() -> bool,
}
impl<'a> LintResources<'a> {
    pub(super) fn new(root: &Path, limits: LintLimits, canceled: &'a dyn Fn() -> bool) -> Self {
        Self {
            root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
            requested_root: root.to_path_buf(),
            limits,
            usage: RefCell::new(Usage::default()),
            canceled,
        }
    }
    pub(super) fn read(&self, path: &Path) -> io::Result<String> {
        let result = self
            .read_document(path)
            .map_err(|error| self.document_error(path, error));
        if let Err(error) = &result {
            self.omit(error.to_string());
        }
        result
    }
    fn document_error(&self, path: &Path, error: io::Error) -> io::Error {
        let relative = path
            .strip_prefix(&self.root)
            .or_else(|_| path.strip_prefix(&self.requested_root))
            .unwrap_or(path);
        let message = error
            .to_string()
            .replace(&path.display().to_string(), &relative.display().to_string());
        io::Error::new(error.kind(), message)
    }

    fn read_document(&self, path: &Path) -> io::Result<String> {
        self.active()?;
        let allowance = self.reserve_read()?;
        let bytes = self.read_bytes(path, allowance)?;
        let mut usage = self.usage.borrow_mut();
        usage.reserved -= allowance - bytes.len();
        usage.captured += bytes.len();
        String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
    fn read_bytes(&self, path: &Path, allowance: usize) -> io::Result<Vec<u8>> {
        let mut file = crate::bounded_file::open_regular_file_within(&self.requested_root, path)?;
        let initial_size = file.metadata()?.len();
        if initial_size > allowance as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} exceeds the maximum supported size of {allowance} bytes",
                    path.display()
                ),
            ));
        }
        let mut bytes = Vec::with_capacity(allowance.min(64 * 1024));
        (&mut file).take(allowance as u64).read_to_end(&mut bytes)?;
        if file.metadata()?.len() != initial_size || bytes.len() as u64 != initial_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pack document changed size while being read",
            ));
        }
        Ok(bytes)
    }

    fn reserve_read(&self) -> io::Result<usize> {
        let mut usage = self.usage.borrow_mut();
        let allowance = self
            .limits
            .per_file
            .min(self.limits.bytes.saturating_sub(usage.reserved));
        if allowance == 0 {
            return Err(io::Error::other("pack read-byte limit reached"));
        }
        usage.reserved += allowance;
        Ok(allowance)
    }
    pub(super) fn active(&self) -> io::Result<()> {
        if !(self.canceled)() {
            return Ok(());
        }
        self.usage.borrow_mut().canceled = true;
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "pack inspection canceled",
        ))
    }
    fn entry(&self) -> io::Result<()> {
        self.active()?;
        let mut usage = self.usage.borrow_mut();
        if usage.entries >= self.limits.entries {
            return Err(io::Error::other("pack walk-entry limit reached"));
        }
        usage.entries += 1;
        Ok(())
    }
    pub(super) fn omit(&self, reason: impl Into<String>) {
        let mut usage = self.usage.borrow_mut();
        usage.omissions += 1;
        if usage.reasons.len() < 16 {
            usage.reasons.insert(reason.into());
        }
    }
    pub(super) fn optional_directory(&self, path: &Path) -> bool {
        match crate::bounded_file::read_dir_within(&self.requested_root, path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                self.omit(format!("{}: {error}", path.display()));
                false
            }
        }
    }
    pub(super) fn partial(&self) -> bool {
        self.usage.borrow().omissions > 0
    }
    pub(super) fn coverage(&self) -> Value {
        let usage = self.usage.borrow();
        json!({"complete":usage.omissions == 0,"entriesExamined":usage.entries,
            "capturedReadBytes":usage.captured,"reservedReadBytes":usage.reserved,
            "omittedChecks":usage.omissions,"ignoredHiddenEntries":usage.hidden,
            "canceled":usage.canceled,"reasonSamples":usage.reasons,
            "maxWalkEntries":self.limits.entries,"maxBytesPerFile":self.limits.per_file,"maxReadBytes":self.limits.bytes,
            "meaning":"Pack schema, direct sibling model documents, prompt destinations and selected shard file counts. This is not repository scan coverage."})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_zero_overflow_and_invalid_types() {
        for input in [
            json!({"maxWalkEntries":0}),
            json!({"maxWalkEntries":100001}),
            json!({"maxReadBytes":536870913_u64}),
            json!({"maxBytesPerFile":"10"}),
        ] {
            assert!(LintLimits::parse(&input).is_err());
        }
    }

    #[test]
    fn failed_reads_keep_reservations_and_invalid_utf8_counts_captured_bytes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("large"), [0; 12]).unwrap();
        std::fs::write(temp.path().join("invalid"), [0xff]).unwrap();
        let resources = LintResources::new(
            temp.path(),
            LintLimits {
                entries: 20,
                per_file: 8,
                bytes: 16,
            },
            &|| false,
        );
        let error = resources.read(&temp.path().join("large")).unwrap_err();
        assert!(error.to_string().starts_with("large exceeds"));
        assert!(!error
            .to_string()
            .contains(&temp.path().display().to_string()));
        assert!(resources.read(&temp.path().join("invalid")).is_err());
        assert_eq!(resources.coverage()["reservedReadBytes"], 9);
        assert_eq!(resources.coverage()["capturedReadBytes"], 1);
        assert!(resources.partial());
    }
}
