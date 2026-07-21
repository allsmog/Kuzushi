use super::checked_run_artifact_path;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The observable state of a containment-checked run artifact read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunArtifactRead<T> {
    Missing { path: PathBuf },
    Ready { path: PathBuf, value: T },
    NonFile { path: PathBuf },
    Unsafe { error: String },
    Unreadable { path: PathBuf, error: String },
}

pub type RunArtifactBytesRead = RunArtifactRead<Vec<u8>>;
pub type RunArtifactTextRead = RunArtifactRead<String>;
pub const MAX_RUN_ARTIFACT_READ_BYTES: u64 = 64 * 1024 * 1024;

impl<T> RunArtifactRead<T> {
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Missing { path }
            | Self::Ready { path, .. }
            | Self::NonFile { path }
            | Self::Unreadable { path, .. } => Some(path),
            Self::Unsafe { .. } => None,
        }
    }

    /// Produce a display label without reflecting an unvalidated path.
    pub fn display_path(&self) -> String {
        self.path()
            .map_or_else(|| "<unsafe run artifact path>".to_string(), escaped_path)
    }

    pub fn require(self, label: &str) -> anyhow::Result<(PathBuf, T)> {
        match self {
            Self::Ready { path, value } => Ok((path, value)),
            Self::Missing { path } => Err(anyhow::anyhow!(
                "{label} is missing: {}",
                escaped_path(&path)
            )),
            other => Err(non_readable_artifact_error(other, label)),
        }
    }
}

/// Resolve a run artifact for display.
///
/// Call the typed readers for I/O; they repeat containment checks and open the
/// final file without following a symlink.
pub fn resolve_run_artifact_path(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
) -> anyhow::Result<PathBuf> {
    checked_run_artifact_path(target, run_id, artifact)
}

pub fn read_run_artifact_bytes(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
) -> RunArtifactBytesRead {
    let path = match resolve_run_artifact_path(target, run_id, artifact) {
        Ok(path) => path,
        Err(error) => {
            return RunArtifactRead::Unsafe {
                error: escape_terminal_controls(&error.to_string()),
            };
        }
    };
    read_checked_artifact(path)
}

pub fn read_run_artifact_text(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
) -> RunArtifactTextRead {
    match read_run_artifact_bytes(target, run_id, artifact) {
        RunArtifactRead::Ready { path, value } => decode_artifact_text(path, value),
        RunArtifactRead::Missing { path } => RunArtifactRead::Missing { path },
        RunArtifactRead::NonFile { path } => RunArtifactRead::NonFile { path },
        RunArtifactRead::Unsafe { error } => RunArtifactRead::Unsafe { error },
        RunArtifactRead::Unreadable { path, error } => RunArtifactRead::Unreadable { path, error },
    }
}

pub(super) fn read_run_artifact_text_or_empty(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
    label: &str,
) -> anyhow::Result<String> {
    match read_run_artifact_text(target, run_id, artifact) {
        RunArtifactRead::Ready { value, .. } => Ok(value),
        RunArtifactRead::Missing { .. } => Ok(String::new()),
        other => Err(non_readable_artifact_error(other, label)),
    }
}

pub(super) fn read_run_artifact_text_required(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: impl AsRef<Path>,
    label: &str,
) -> anyhow::Result<(PathBuf, String)> {
    read_run_artifact_text(target, run_id, artifact).require(label)
}

fn non_readable_artifact_error<T>(read: RunArtifactRead<T>, label: &str) -> anyhow::Error {
    match read {
        RunArtifactRead::NonFile { path } => {
            anyhow::anyhow!("{label} is not a file: {}", escaped_path(&path))
        }
        RunArtifactRead::Unsafe { error } => anyhow::anyhow!("{label} is unsafe: {error}"),
        RunArtifactRead::Unreadable { path, error } => {
            anyhow::anyhow!("Could not read {label} {}: {error}", escaped_path(&path))
        }
        RunArtifactRead::Missing { .. } | RunArtifactRead::Ready { .. } => {
            unreachable!("readable states are handled by the caller")
        }
    }
}

fn read_checked_artifact(path: PathBuf) -> RunArtifactBytesRead {
    let metadata = match artifact_metadata(&path) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return RunArtifactRead::Missing { path },
        Err(error) => return unreadable(path, error),
    };
    if let Err(state) = validate_regular_artifact(&path, &metadata) {
        return state;
    }
    read_regular_artifact(path)
}

fn artifact_metadata(path: &Path) -> std::io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validate_regular_artifact(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), RunArtifactBytesRead> {
    if metadata.file_type().is_symlink() {
        return Err(RunArtifactRead::Unsafe {
            error: format!(
                "Run artifact must not be a symlink: {}",
                escape_terminal_controls(&path.display().to_string())
            ),
        });
    }
    if !metadata.is_file() {
        return Err(RunArtifactRead::NonFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > MAX_RUN_ARTIFACT_READ_BYTES {
        return Err(too_large(path));
    }
    Ok(())
}

fn read_regular_artifact(path: PathBuf) -> RunArtifactBytesRead {
    match read_file_bytes(&path) {
        Ok(value) => RunArtifactRead::Ready { path, value },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            RunArtifactRead::Missing { path }
        }
        Err(error) => unreadable(path, error),
    }
}

fn too_large(path: &Path) -> RunArtifactBytesRead {
    RunArtifactRead::Unreadable {
        path: path.to_path_buf(),
        error: format!("Run artifact exceeds the {MAX_RUN_ARTIFACT_READ_BYTES}-byte read limit"),
    }
}

fn decode_artifact_text(path: PathBuf, value: Vec<u8>) -> RunArtifactTextRead {
    match String::from_utf8(value) {
        Ok(value) => RunArtifactRead::Ready { path, value },
        Err(error) => RunArtifactRead::Unreadable {
            path,
            error: format!("Run artifact is not valid UTF-8: {error}"),
        },
    }
}

fn unreadable<T>(path: PathBuf, error: std::io::Error) -> RunArtifactRead<T> {
    RunArtifactRead::Unreadable {
        path,
        error: error.to_string(),
    }
}

fn escape_terminal_controls(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
}

fn escaped_path(path: &Path) -> String {
    escape_terminal_controls(&path.display().to_string())
}

fn read_file_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = open_file_without_following_symlink(path)?;
    let mut reader = file.take(MAX_RUN_ARTIFACT_READ_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RUN_ARTIFACT_READ_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "run artifact grew beyond the bounded read limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_file_without_following_symlink(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_file_without_following_symlink(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}
