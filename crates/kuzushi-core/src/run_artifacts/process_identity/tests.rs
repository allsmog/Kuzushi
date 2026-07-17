use super::identity_read::{
    self, ProcessIdentityBindingMismatchKind, ProcessIdentityReadIssueKind,
    ProcessIdentityReadOutcome,
};
use super::*;
use std::fs;

fn birth_identity(token: &str) -> ProcessBirthIdentity {
    ProcessBirthIdentity {
        platform: "test".to_string(),
        boot_id: Some("boot".to_string()),
        start_token: token.to_string(),
    }
}

fn persisted_identity(process_id: u32, token: &str) -> PersistedProcessIdentity {
    PersistedProcessIdentity {
        schema_version: PROCESS_IDENTITY_SCHEMA_VERSION,
        process_id,
        identity: birth_identity(token),
    }
}

fn write_test_identity(target: &Path, run_id: &str, identity: &PersistedProcessIdentity) {
    super::super::ensure_run_dir(target, run_id).unwrap();
    write_identity(target, run_id, identity).unwrap();
}

#[test]
fn identity_read_distinguishes_absence_and_valid_evidence() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "run-identity-read";
    let expected = birth_identity("one");

    assert_eq!(
        identity_read::read(tmp.path(), run_id, 7, Some(&expected)),
        ProcessIdentityReadOutcome::Absent
    );

    write_test_identity(tmp.path(), run_id, &persisted_identity(7, "one"));
    assert_eq!(
        identity_read::read(tmp.path(), run_id, 7, Some(&expected)),
        ProcessIdentityReadOutcome::Valid
    );
}

#[test]
fn identity_read_classifies_invalid_content_exactly() {
    let cases = [
        (
            "malformed",
            b"{".to_vec(),
            ProcessIdentityReadIssueKind::InvalidJson,
        ),
        (
            "unknown-field",
            br#"{"schemaVersion":1,"processId":7,"identity":{"platform":"test","bootId":"boot","startToken":"one"},"extra":true}"#
                .to_vec(),
            ProcessIdentityReadIssueKind::InvalidSchema,
        ),
        (
            "invalid-utf8",
            vec![0xff],
            ProcessIdentityReadIssueKind::InvalidUtf8,
        ),
        (
            "empty-token",
            br#"{"schemaVersion":1,"processId":7,"identity":{"platform":"test","bootId":"boot","startToken":""}}"#
                .to_vec(),
            ProcessIdentityReadIssueKind::InvalidSchema,
        ),
        (
            "oversized",
            vec![b' '; MAX_PROCESS_IDENTITY_BYTES + 1],
            ProcessIdentityReadIssueKind::Oversized,
        ),
    ];

    for (run_id, body, expected_kind) in cases {
        let tmp = tempfile::tempdir().unwrap();
        super::super::ensure_run_dir(tmp.path(), run_id).unwrap();
        fs::write(identity_path(tmp.path(), run_id), body).unwrap();

        let ProcessIdentityReadOutcome::Invalid(issue) =
            identity_read::read(tmp.path(), run_id, 7, Some(&birth_identity("one")))
        else {
            panic!("{run_id} should be invalid");
        };
        assert_eq!(issue.kind, expected_kind, "{run_id}");
    }
}

#[test]
fn identity_read_distinguishes_binding_mismatches() {
    let tmp = tempfile::tempdir().unwrap();
    write_test_identity(
        tmp.path(),
        "run-process-id-mismatch",
        &persisted_identity(8, "one"),
    );
    write_test_identity(
        tmp.path(),
        "run-birth-mismatch",
        &persisted_identity(7, "other"),
    );

    let ProcessIdentityReadOutcome::BindingMismatch(process_id) = identity_read::read(
        tmp.path(),
        "run-process-id-mismatch",
        7,
        Some(&birth_identity("one")),
    ) else {
        panic!("process id mismatch should be typed");
    };
    let ProcessIdentityReadOutcome::BindingMismatch(birth) = identity_read::read(
        tmp.path(),
        "run-birth-mismatch",
        7,
        Some(&birth_identity("one")),
    ) else {
        panic!("birth mismatch should be typed");
    };

    assert_eq!(
        process_id.kind,
        ProcessIdentityBindingMismatchKind::ProcessId
    );
    assert_eq!(
        birth.kind,
        ProcessIdentityBindingMismatchKind::BirthIdentity
    );
}

#[test]
fn identity_read_rejects_directory_sidecars() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "run-directory-identity";
    super::super::ensure_run_dir(tmp.path(), run_id).unwrap();
    fs::create_dir(identity_path(tmp.path(), run_id)).unwrap();

    let ProcessIdentityReadOutcome::Invalid(issue) =
        identity_read::read(tmp.path(), run_id, 7, None)
    else {
        panic!("directory should be invalid");
    };
    assert_eq!(issue.kind, ProcessIdentityReadIssueKind::UnsafePath);
}

#[cfg(unix)]
#[test]
fn identity_read_rejects_symlink_sidecars() {
    let tmp = tempfile::tempdir().unwrap();
    let run_id = "run-symlink-identity";
    super::super::ensure_run_dir(tmp.path(), run_id).unwrap();
    let destination = tmp.path().join("external-identity.json");
    fs::write(&destination, b"{}").unwrap();
    std::os::unix::fs::symlink(destination, identity_path(tmp.path(), run_id)).unwrap();

    let ProcessIdentityReadOutcome::Invalid(issue) =
        identity_read::read(tmp.path(), run_id, 7, None)
    else {
        panic!("symlink should be invalid");
    };
    assert_eq!(issue.kind, ProcessIdentityReadIssueKind::UnsafePath);
}

#[test]
fn identity_read_preserves_unreadable_io_as_a_distinct_issue() {
    let issue = identity_read::classify_read_error(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    ));

    assert_eq!(issue.kind, ProcessIdentityReadIssueKind::Unreadable);
    assert!(issue.detail.contains("denied"));
}

#[test]
fn ownership_decision_table_only_falls_back_for_usable_evidence() {
    let invalid = ProcessIdentityReadOutcome::Invalid(identity_read::ProcessIdentityReadIssue {
        kind: ProcessIdentityReadIssueKind::InvalidJson,
        detail: "invalid".to_string(),
    });
    let mismatch = ProcessIdentityReadOutcome::BindingMismatch(
        identity_read::ProcessIdentityBindingMismatch {
            kind: ProcessIdentityBindingMismatchKind::ProcessId,
            detail: "mismatch".to_string(),
        },
    );

    assert_eq!(
        decide_original_process_status(ProcessObservation::Dead, ProcessIdentityReadOutcome::Valid),
        OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::ProcessDead)
    );
    for observation in [
        ProcessObservation::Unknown,
        ProcessObservation::Alive(None),
        ProcessObservation::Alive(Some(birth_identity("one"))),
    ] {
        assert_eq!(
            decide_original_process_status(observation, ProcessIdentityReadOutcome::Absent),
            OriginalProcessStatus::OriginalOwner
        );
    }
    assert_eq!(
        decide_original_process_status(ProcessObservation::Unknown, invalid),
        OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::IdentityRejected(
            "invalid".to_string()
        ))
    );
    assert_eq!(
        decide_original_process_status(ProcessObservation::Alive(None), mismatch),
        OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::IdentityRejected(
            "mismatch".to_string()
        ))
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn invalid_live_pid_sidecars_are_repaired_with_actionable_diagnostics() {
    let process_id = std::process::id();
    let cases = [
        ("malformed", b"{".to_vec(), "invalid JSON"),
        (
            "unknown-field",
            format!(
                r#"{{"schemaVersion":1,"processId":{process_id},"identity":{{"platform":"test","bootId":null,"startToken":"one"}},"extra":true}}"#
            )
            .into_bytes(),
            "invalid schema",
        ),
        ("invalid-utf8", vec![0xff], "not valid UTF-8"),
        (
            "oversized",
            vec![b' '; MAX_PROCESS_IDENTITY_BYTES + 1],
            "exceeds 2048 bytes",
        ),
    ];

    for (run_id, body, expected_detail) in cases {
        assert_live_process_sidecar_rejected(run_id, body, expected_detail);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[test]
fn directory_live_pid_sidecar_is_repaired() {
    let tmp = running_summary_fixture("run-live-directory");
    let path = identity_path(tmp.path(), "run-live-directory");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    assert_repaired_with_detail(tmp.path(), "run-live-directory", "not a regular file");
}

#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
#[test]
fn symlink_live_pid_sidecar_is_repaired() {
    let tmp = running_summary_fixture("run-live-symlink");
    let path = identity_path(tmp.path(), "run-live-symlink");
    let destination = tmp.path().join("external-process-identity.json");
    fs::write(&destination, fs::read(&path).unwrap()).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(destination, path).unwrap();

    assert_repaired_with_detail(tmp.path(), "run-live-symlink", "symlink");
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn assert_live_process_sidecar_rejected(run_id: &str, body: Vec<u8>, expected_detail: &str) {
    let tmp = running_summary_fixture(run_id);
    fs::write(identity_path(tmp.path(), run_id), body).unwrap();
    assert_repaired_with_detail(tmp.path(), run_id, expected_detail);
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn running_summary_fixture(run_id: &str) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let summary = super::super::RunSummary::running(run_id, "scan", None, "target")
        .with_process_id(std::process::id());
    super::super::write_run_summary(tmp.path(), &summary).unwrap();
    assert!(identity_path(tmp.path(), run_id).is_file());
    tmp
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn assert_repaired_with_detail(target: &Path, run_id: &str, expected_detail: &str) {
    let loaded = super::super::load_run_summary(target, run_id).unwrap();
    assert_eq!(loaded.status, "interrupted");
    let error = loaded.error.unwrap();
    assert!(error.contains("cannot be verified as the original owner"));
    assert!(error.contains(expected_detail), "{error}");
}
