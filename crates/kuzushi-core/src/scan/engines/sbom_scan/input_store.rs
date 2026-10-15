//! One contained source capture and byte allowance shared by every parser stage.
use super::{SbomInputInspection, SbomInputReceipt, SbomScanOptions, ScanCancellation};
use crate::workspace::InventoryRoot;
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct CapturedInput {
    bytes: Arc<Vec<u8>>,
    receipt: SbomInputReceipt,
}

pub(super) struct SbomInputs {
    path: PathBuf,
    requested_path: PathBuf,
    reader: InventoryRoot,
    options: SbomScanOptions,
    cancellation: ScanCancellation,
    reserved: Cell<u64>,
    read: Cell<u64>,
    captured: RefCell<BTreeMap<PathBuf, CapturedInput>>,
}

impl Deref for SbomInputs {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl SbomInputs {
    pub(super) fn new(
        path: &Path,
        options: SbomScanOptions,
        cancellation: ScanCancellation,
    ) -> io::Result<Self> {
        let requested_path = path.to_owned();
        let path = path.canonicalize()?;
        Ok(Self {
            reader: InventoryRoot::new(&path)?,
            path,
            requested_path,
            options,
            cancellation,
            reserved: Cell::new(0),
            read: Cell::new(0),
            captured: RefCell::new(BTreeMap::new()),
        })
    }

    pub(super) fn verify_root(&self) -> io::Result<()> {
        self.reader.verify_current_root()?;
        if self.requested_path.canonicalize()? != self.path {
            return Err(io::Error::other(
                "sbom-scan target changed during inventory",
            ));
        }
        Ok(())
    }

    pub(super) fn bytes(&self, path: &Path) -> io::Result<Arc<Vec<u8>>> {
        check_active(&self.cancellation)?;
        self.verify_root()?;
        let relative =
            crate::bounded_file::relative_path_within(&self.requested_path, &self.path, path)?;
        let relative = relative
            .components()
            .filter(|component| matches!(component, std::path::Component::Normal(_)))
            .map(|component| component.as_os_str())
            .collect::<PathBuf>();
        if let Some(input) = self.captured.borrow().get(&relative) {
            return Ok(Arc::clone(&input.bytes));
        }
        let bytes = Arc::new(self.capture(&self.path.join(&relative))?);
        self.verify_root()?;
        let receipt = input_receipt(&relative, &bytes);
        self.captured.borrow_mut().insert(
            relative,
            CapturedInput {
                bytes: Arc::clone(&bytes),
                receipt,
            },
        );
        Ok(bytes)
    }

    fn capture(&self, path: &Path) -> io::Result<Vec<u8>> {
        let mut file = self.reader.open_file(path)?;
        let length = file.metadata()?.len();
        self.reserve(path, length)?;
        let bytes = read_capture(&mut file, length, &self.cancellation, &self.read)?;
        if file.metadata()?.len() != length {
            return Err(io::Error::other(
                "sbom-scan input changed size during capture",
            ));
        }
        Ok(bytes)
    }

    fn reserve(&self, path: &Path, length: u64) -> io::Result<()> {
        if length > self.options.max_file_bytes as u64 {
            return Err(io::Error::other(format!(
                "sbom-scan input {} exceeds maximum supported size: maxFileBytes {}",
                path.display(),
                self.options.max_file_bytes
            )));
        }
        let remaining = self.options.max_total_bytes as u64 - self.reserved.get();
        if length > remaining {
            return Err(io::Error::other(format!("sbom-scan maxTotalBytes {} reached: {} bytes reserved; {} needs {length} more. Review input limits before retrying.", self.options.max_total_bytes, self.reserved.get(), path.display())));
        }
        self.reserved.set(self.reserved.get() + length);
        Ok(())
    }

    pub(super) fn inspection(&self) -> SbomInputInspection {
        let captured = self.captured.borrow();
        let inputs = captured
            .values()
            .map(|value| value.receipt.clone())
            .collect::<Vec<_>>();
        let mut hash = Sha256::new();
        for (path, input) in captured.iter() {
            let bytes = path.as_os_str().as_encoded_bytes();
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
            hash.update(input.receipt.sha256.as_bytes());
        }
        let digest = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        SbomInputInspection {
            limits: self.options.clone(),
            reserved_source_bytes: self.reserved.get(),
            source_bytes_read: self.read.get(),
            captured_files: inputs.len(),
            captured_bytes: inputs.iter().map(|input| input.size_bytes).sum(),
            inputs,
            captured_input_sha256: format!("sha256:{digest}"),
        }
    }
}

fn input_receipt(path: &Path, bytes: &[u8]) -> SbomInputReceipt {
    SbomInputReceipt {
        path: path.to_string_lossy().replace('\\', "/"),
        encoded_path_sha256: path
            .to_str()
            .is_none()
            .then(|| digest(path.as_os_str().as_encoded_bytes())),
        size_bytes: bytes.len(),
        sha256: digest(bytes),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(bytes)
    )
}

fn check_active(cancellation: &ScanCancellation) -> io::Result<()> {
    cancellation.wait_if_paused();
    if cancellation.is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "sbom-scan scan cancelled",
        ));
    }
    Ok(())
}

fn read_capture(
    reader: &mut impl Read,
    length: u64,
    cancellation: &ScanCancellation,
    consumed: &Cell<u64>,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(length as usize);
    let mut buffer = [0; 64 * 1024];
    while bytes.len() < length as usize {
        check_active(cancellation)?;
        let capacity = buffer.len().min(length as usize - bytes.len());
        let count = reader.read(&mut buffer[..capacity])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "sbom-scan input became shorter during capture",
            ));
        }
        consumed.set(consumed.get() + count as u64);
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
