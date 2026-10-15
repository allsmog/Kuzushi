use std::path::PathBuf;

pub fn executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).find_map(|dir| executable_in_dir(&dir, name))
}

fn executable_in_dir(dir: &std::path::Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if executable_file(&candidate) {
        return Some(candidate);
    }
    #[cfg(windows)]
    {
        let candidate = dir.join(format!("{name}.exe"));
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

pub(crate) fn executable_available(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }
    let path = std::path::Path::new(command);
    if path.components().count() > 1 || path.is_absolute() {
        return executable_file(path);
    }
    executable_on_path(command).is_some()
}

fn executable_file(path: &std::path::Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && executable_permissions(&metadata))
}

#[cfg(unix)]
fn executable_permissions(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_permissions(_metadata: &std::fs::Metadata) -> bool {
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn executable_lookup_rejects_directories_and_files_without_execute_permission() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("owned-scanner");
        std::fs::write(&path, "Owned inert file. Never invoked.").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(executable_in_dir(temp.path(), "owned-scanner").is_none());
        assert!(!executable_available(path.to_str().unwrap()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            executable_in_dir(temp.path(), "owned-scanner"),
            Some(path.clone())
        );
        assert!(executable_available(path.to_str().unwrap()));
        assert!(!executable_available(temp.path().to_str().unwrap()));
        assert!(!executable_available(""));
    }
}
