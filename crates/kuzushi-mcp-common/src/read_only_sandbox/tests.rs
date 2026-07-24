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

#[cfg(unix)]
fn authorized(path: &Path) -> crate::AuthorizedDirectory {
    crate::ReadRootCapability::new([path.to_path_buf()])
        .unwrap()
        .authorize_directory(path)
        .unwrap()
}

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
    tokio::time::timeout(Duration::from_secs(2), terminate_child_group(&mut child))
        .await
        .expect("sandbox group did not terminate");
    assert!(child.try_wait().unwrap().is_some());
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

#[cfg(unix)]
#[tokio::test]
async fn child_cannot_rewrite_a_helper_in_its_authorized_tool_bundle() {
    use std::os::unix::fs::PermissionsExt;

    if !sandbox_available().await {
        return;
    }
    let tool = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    let writable = tempfile::tempdir().unwrap();
    let launcher = tool.path().join("runner");
    let helper = tool.path().join("helper");
    let receipt = writable.path().join("receipt");
    std::fs::write(&helper, "trusted").unwrap();
    std::fs::write(
        &launcher,
        "#!/bin/sh\nif printf malicious > \"$1\"; then printf rewritable > \"$2\"; else printf blocked > \"$2\"; fi\n",
    )
    .unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o700)).unwrap();
    let access = RestrictedSandboxAccess {
        working_directory: authorized(input.path()),
        tool_root: authorized(tool.path()),
        read_only: Vec::new(),
        read_write: vec![authorized(writable.path())],
        environment: Vec::new(),
    };
    let sandboxed = restricted_command(&launcher, [&helper, &receipt], access)
        .await
        .unwrap();
    let (mut child, _scratch) = sandboxed.spawn("rewrite fixture").unwrap();

    assert!(child.wait().await.unwrap().success());
    assert_eq!(std::fs::read_to_string(&helper).unwrap(), "trusted");
    assert_eq!(std::fs::read_to_string(&receipt).unwrap(), "blocked");
}

#[cfg(target_os = "macos")]
#[test]
fn restricted_seatbelt_command_pins_only_approved_codeql_environment() {
    use std::os::unix::fs::PermissionsExt;

    let tool = tempfile::tempdir().unwrap();
    let input = tempfile::tempdir().unwrap();
    let launcher = tool.path().join("codeql");
    std::fs::write(&launcher, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o700)).unwrap();
    let tool_root = authorized(tool.path());
    let canonical_tool = tool_root.path().to_path_buf();
    let access = RestrictedSandboxAccess {
        working_directory: authorized(input.path()),
        tool_root,
        read_only: Vec::new(),
        read_write: Vec::new(),
        environment: vec![("CODEQL_DIST".into(), canonical_tool.as_os_str().to_owned())],
    };
    let sandboxed = super::backend::build_restricted_command(
        ReadOnlySandboxBackend::MacosSeatbelt,
        &launcher,
        std::iter::empty::<&OsStr>(),
        access,
    )
    .unwrap();
    let environment = sandboxed.command.as_std().get_envs().collect::<Vec<_>>();

    assert!(environment.iter().any(|(name, value)| {
        *name == OsStr::new("CODEQL_DIST") && value == &Some(canonical_tool.as_os_str())
    }));
    assert!(!environment
        .iter()
        .any(|(name, _)| *name == OsStr::new("CODEQL_JAVA_HOME")));
}
