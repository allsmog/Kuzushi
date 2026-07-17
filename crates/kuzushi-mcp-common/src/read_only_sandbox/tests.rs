#[cfg(unix)]
use super::backend::build_command;
#[cfg(target_os = "macos")]
use super::backend::{parameter, MACOS_PROFILE};
use super::*;
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;

#[test]
fn executable_resolution_rejects_directories() {
    let directory = tempfile::tempdir().unwrap();

    let error = resolve_regular_executable(directory.path().as_os_str()).unwrap_err();

    assert!(error.to_string().contains("not a regular file"));
}

#[cfg(unix)]
#[tokio::test]
async fn long_lived_sandbox_process_uses_a_dedicated_killable_group() {
    let Some(backend) = probe::self_probe_candidate().await else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let capability = crate::ReadRootCapability::new([root.path().to_path_buf()]).unwrap();
    let input = capability.authorize_directory(root.path()).unwrap();
    let sandboxed = build_command(
        backend,
        Path::new("/bin/sh"),
        [OsStr::new("-c"), OsStr::new("sleep 30 & wait")],
        input,
    )
    .unwrap();
    let (mut child, _scratch) = sandboxed.spawn("group fixture").unwrap();
    let pid = child.id().unwrap();

    // SAFETY: the child is live and its process-group identity is read-only here.
    assert_eq!(
        unsafe { libc::getpgid(pid as libc::pid_t) },
        pid as libc::pid_t
    );
    // SAFETY: the launcher and its descendant were placed in this dedicated group.
    unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) };
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("sandbox group did not terminate")
        .unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn ambient_path_cannot_select_the_bubblewrap_launcher() {
    use super::backend::trusted_bwrap;
    use std::os::unix::fs::PermissionsExt;

    let shadow = tempfile::tempdir().unwrap();
    let fake = shadow.path().join("bwrap");
    std::fs::write(&fake, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    let selected = trusted_bwrap();

    assert_ne!(selected.as_deref(), Some(fake.as_path()));
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_paths_are_parameters_not_profile_source() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("quote\" slash\\ newline\nroot");
    std::fs::create_dir(&root).unwrap();
    let capability = crate::ReadRootCapability::new([root.clone()]).unwrap();
    let input = capability.authorize_directory(&root).unwrap();
    let canonical_root = input.path().to_path_buf();
    let sandboxed = build_command(
        ReadOnlySandboxBackend::MacosSeatbelt,
        Path::new("/bin/sh"),
        [OsStr::new("-c"), OsStr::new("true")],
        input,
    )
    .unwrap();
    let args = sandboxed
        .command
        .as_std()
        .get_args()
        .map(OsStr::to_owned)
        .collect::<Vec<_>>();
    let target = parameter("TARGET_ROOT", &canonical_root);

    assert!(args.contains(&target));
    assert!(!MACOS_PROFILE.contains(root.to_string_lossy().as_ref()));
}
