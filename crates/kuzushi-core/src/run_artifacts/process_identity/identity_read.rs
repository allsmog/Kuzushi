use super::{
    PersistedProcessIdentity, ProcessBirthIdentity, MAX_PROCESS_IDENTITY_BYTES,
    PROCESS_IDENTITY_LEAF, PROCESS_IDENTITY_SCHEMA_VERSION,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessIdentityReadIssueKind {
    UnsafePath,
    Oversized,
    Unreadable,
    InvalidUtf8,
    InvalidJson,
    InvalidSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessIdentityReadIssue {
    pub(super) kind: ProcessIdentityReadIssueKind,
    pub(super) detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessIdentityBindingMismatchKind {
    ProcessId,
    BirthIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessIdentityBindingMismatch {
    pub(super) kind: ProcessIdentityBindingMismatchKind,
    pub(super) detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessIdentityReadOutcome {
    Absent,
    Valid,
    Invalid(ProcessIdentityReadIssue),
    BindingMismatch(ProcessIdentityBindingMismatch),
}

enum IdentityFile {
    Absent,
    Bytes(Vec<u8>),
}

pub(super) fn read(
    target: &Path,
    run_id: &str,
    expected_process_id: u32,
    observed_identity: Option<&ProcessBirthIdentity>,
) -> ProcessIdentityReadOutcome {
    let path = match super::checked_run_artifact_path(target, run_id, PROCESS_IDENTITY_LEAF) {
        Ok(path) => path,
        Err(error) => {
            return invalid(
                ProcessIdentityReadIssueKind::UnsafePath,
                unsafe_path_detail(&error.to_string()),
            )
        }
    };
    read_path(&path, expected_process_id, observed_identity)
}

fn unsafe_path_detail(error: &str) -> String {
    if error.contains("symlink") {
        return "process identity sidecar is a symlink".to_string();
    }
    "process identity sidecar path is unsafe".to_string()
}

fn read_path(
    path: &Path,
    expected_process_id: u32,
    observed_identity: Option<&ProcessBirthIdentity>,
) -> ProcessIdentityReadOutcome {
    match load_identity_file(path) {
        Ok(IdentityFile::Absent) => ProcessIdentityReadOutcome::Absent,
        Ok(IdentityFile::Bytes(bytes)) => {
            parse_and_bind(&bytes, expected_process_id, observed_identity)
        }
        Err(issue) => ProcessIdentityReadOutcome::Invalid(issue),
    }
}

fn load_identity_file(path: &Path) -> Result<IdentityFile, ProcessIdentityReadIssue> {
    let Some(metadata) = identity_metadata(path)? else {
        return Ok(IdentityFile::Absent);
    };
    validate_identity_metadata(&metadata)?;
    crate::bounded_file::read_regular_bytes(path, MAX_PROCESS_IDENTITY_BYTES)
        .map(IdentityFile::Bytes)
        .map_err(unreadable_file)
}

fn identity_metadata(path: &Path) -> Result<Option<fs::Metadata>, ProcessIdentityReadIssue> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(issue(
            ProcessIdentityReadIssueKind::Unreadable,
            format!("could not inspect process identity sidecar: {error}"),
        )),
    }
}

fn validate_identity_metadata(metadata: &fs::Metadata) -> Result<(), ProcessIdentityReadIssue> {
    reject_unsafe_path_type(metadata)?;
    if metadata.len() > MAX_PROCESS_IDENTITY_BYTES as u64 {
        return Err(oversized_issue());
    }
    Ok(())
}

fn reject_unsafe_path_type(metadata: &fs::Metadata) -> Result<(), ProcessIdentityReadIssue> {
    if metadata.file_type().is_symlink() {
        return Err(issue(
            ProcessIdentityReadIssueKind::UnsafePath,
            "process identity sidecar is a symlink".to_string(),
        ));
    }
    if !metadata.is_file() {
        return Err(issue(
            ProcessIdentityReadIssueKind::UnsafePath,
            "process identity sidecar is not a regular file".to_string(),
        ));
    }
    Ok(())
}

fn unreadable_file(error: std::io::Error) -> ProcessIdentityReadIssue {
    if error.kind() == std::io::ErrorKind::InvalidData {
        return oversized_issue();
    }
    issue(
        ProcessIdentityReadIssueKind::Unreadable,
        format!("could not read process identity sidecar: {error}"),
    )
}

fn oversized_issue() -> ProcessIdentityReadIssue {
    issue(
        ProcessIdentityReadIssueKind::Oversized,
        format!("process identity sidecar exceeds {MAX_PROCESS_IDENTITY_BYTES} bytes"),
    )
}

fn parse_and_bind(
    bytes: &[u8],
    expected_process_id: u32,
    observed_identity: Option<&ProcessBirthIdentity>,
) -> ProcessIdentityReadOutcome {
    match parse_identity(bytes) {
        Ok(identity) => bind_identity(identity, expected_process_id, observed_identity),
        Err(issue) => ProcessIdentityReadOutcome::Invalid(issue),
    }
}

fn parse_identity(bytes: &[u8]) -> Result<PersistedProcessIdentity, ProcessIdentityReadIssue> {
    let body = String::from_utf8(bytes.to_vec()).map_err(|_| {
        issue(
            ProcessIdentityReadIssueKind::InvalidUtf8,
            "process identity sidecar is not valid UTF-8".to_string(),
        )
    })?;
    serde_json::from_str::<Value>(&body).map_err(|error| {
        issue(
            ProcessIdentityReadIssueKind::InvalidJson,
            format!("process identity sidecar contains invalid JSON: {error}"),
        )
    })?;
    let identity = serde_json::from_str::<PersistedProcessIdentity>(&body).map_err(|error| {
        issue(
            ProcessIdentityReadIssueKind::InvalidSchema,
            format!("process identity sidecar has an invalid schema: {error}"),
        )
    })?;
    validate_identity_schema(identity)
}

fn validate_identity_schema(
    identity: PersistedProcessIdentity,
) -> Result<PersistedProcessIdentity, ProcessIdentityReadIssue> {
    validate_schema_version(&identity)?;
    validate_identity_fields(&identity)?;
    Ok(identity)
}

fn validate_schema_version(
    identity: &PersistedProcessIdentity,
) -> Result<(), ProcessIdentityReadIssue> {
    if identity.schema_version != PROCESS_IDENTITY_SCHEMA_VERSION {
        return Err(issue(
            ProcessIdentityReadIssueKind::InvalidSchema,
            format!(
                "process identity sidecar schema version {} is unsupported",
                identity.schema_version
            ),
        ));
    }
    Ok(())
}

fn validate_identity_fields(
    identity: &PersistedProcessIdentity,
) -> Result<(), ProcessIdentityReadIssue> {
    if identity.identity.platform.trim().is_empty() {
        return Err(invalid_schema("platform must not be empty"));
    }
    if identity.identity.start_token.trim().is_empty() {
        return Err(invalid_schema("startToken must not be empty"));
    }
    if identity
        .identity
        .boot_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(invalid_schema("bootId must not be empty when present"));
    }
    Ok(())
}

fn bind_identity(
    identity: PersistedProcessIdentity,
    expected_process_id: u32,
    observed_identity: Option<&ProcessBirthIdentity>,
) -> ProcessIdentityReadOutcome {
    if identity.process_id != expected_process_id {
        return process_id_mismatch(identity.process_id, expected_process_id);
    }
    if observed_identity.is_some_and(|observed| identity.identity != *observed) {
        return birth_identity_mismatch();
    }
    ProcessIdentityReadOutcome::Valid
}

fn process_id_mismatch(recorded: u32, expected: u32) -> ProcessIdentityReadOutcome {
    ProcessIdentityReadOutcome::BindingMismatch(ProcessIdentityBindingMismatch {
        kind: ProcessIdentityBindingMismatchKind::ProcessId,
        detail: format!(
            "process identity sidecar records process id {recorded}, expected {expected}"
        ),
    })
}

fn birth_identity_mismatch() -> ProcessIdentityReadOutcome {
    ProcessIdentityReadOutcome::BindingMismatch(ProcessIdentityBindingMismatch {
        kind: ProcessIdentityBindingMismatchKind::BirthIdentity,
        detail: "process identity birth token does not match the live process".to_string(),
    })
}

fn invalid(kind: ProcessIdentityReadIssueKind, detail: String) -> ProcessIdentityReadOutcome {
    ProcessIdentityReadOutcome::Invalid(issue(kind, detail))
}

fn issue(kind: ProcessIdentityReadIssueKind, detail: String) -> ProcessIdentityReadIssue {
    ProcessIdentityReadIssue { kind, detail }
}

fn invalid_schema(detail: &str) -> ProcessIdentityReadIssue {
    issue(
        ProcessIdentityReadIssueKind::InvalidSchema,
        format!("process identity sidecar has an invalid schema: {detail}"),
    )
}

#[cfg(test)]
pub(super) fn classify_read_error(error: std::io::Error) -> ProcessIdentityReadIssue {
    unreadable_file(error)
}
