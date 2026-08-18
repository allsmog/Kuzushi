use super::DoctorCheck;
use kuzushi_openai::LangGraphRuntime;
use std::env;
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_WINDOWS_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

pub(crate) fn check_bridge_command(config: &kuzushi_core::V2Config) -> DoctorCheck {
    match LangGraphRuntime::from_config(config, current_dir_for_doctor()) {
        Ok(runtime) => bridge_command_check(runtime.command()),
        Err(error) => DoctorCheck::fail(
            "LangGraph bridge",
            error.to_string(),
            "Set runtime.langgraph_bridge_command to an executable command.",
        ),
    }
}

fn bridge_command_check(command: &[String]) -> DoctorCheck {
    if command.is_empty() {
        return DoctorCheck::fail(
            "LangGraph bridge",
            "bridge command is empty",
            "Set runtime.langgraph_bridge_command to an executable command.",
        );
    }
    let cwd = current_dir_for_doctor();
    let executable = resolve_executable(&command[0], env::var_os("PATH").as_deref(), &cwd);
    let Some(executable) = executable else {
        return DoctorCheck::fail(
            "LangGraph bridge",
            format!("bridge executable {:?} was not found", command[0]),
            "Install Node.js or set runtime.langgraph_bridge_command to an executable bridge.",
        );
    };

    if let Some(failure) = bridge_script_failure(command, &cwd) {
        return failure;
    }

    DoctorCheck::ok(
        "LangGraph bridge",
        format!("{} via {}", command.join(" "), executable.display()),
    )
}

fn bridge_script_failure(command: &[String], cwd: &Path) -> Option<DoctorCheck> {
    let script = command
        .get(1)
        .filter(|arg| arg.ends_with("langgraph-bridge.mjs"))?;
    let script_path = resolve_command_path(script, cwd);
    (!script_path.exists()).then(|| {
        DoctorCheck::fail(
            "LangGraph bridge",
            format!("bridge script {} was not found", script_path.display()),
            "Run from a source checkout, build the npm package, or set runtime.langgraph_bridge_command.",
        )
    })
}

pub(crate) fn current_dir_for_doctor() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn resolve_executable(
    binary: &str,
    path: Option<&std::ffi::OsStr>,
    cwd: &Path,
) -> Option<PathBuf> {
    resolve_executable_for_platform(
        binary,
        path,
        cwd,
        cfg!(windows),
        env::var_os("PATHEXT").as_deref(),
    )
}

fn resolve_executable_for_platform(
    binary: &str,
    path: Option<&OsStr>,
    cwd: &Path,
    windows: bool,
    path_ext: Option<&OsStr>,
) -> Option<PathBuf> {
    let candidate = Path::new(binary);
    if candidate.components().count() > 1 {
        let resolved = resolve_command_path(binary, cwd);
        return executable_candidates(&resolved, windows, path_ext)
            .find(|candidate| is_executable_file(candidate));
    }

    path.into_iter()
        .flat_map(env::split_paths)
        .flat_map(|dir| executable_candidates(&dir.join(binary), windows, path_ext))
        .find(|candidate| is_executable_file(candidate))
}

fn executable_candidates(
    candidate: &Path,
    windows: bool,
    path_ext: Option<&OsStr>,
) -> impl Iterator<Item = PathBuf> {
    let mut candidates = vec![candidate.to_path_buf()];
    if windows && candidate.extension().is_none() {
        candidates.extend(
            windows_executable_extensions(path_ext)
                .map(|extension| candidate.with_extension(extension.trim_start_matches('.'))),
        );
    }
    candidates.into_iter()
}

fn windows_executable_extensions(path_ext: Option<&OsStr>) -> impl Iterator<Item = &str> {
    path_ext
        .and_then(OsStr::to_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_WINDOWS_PATHEXT)
        .split(';')
        .map(str::trim)
        .filter(|extension| !extension.is_empty())
}

pub(crate) fn resolve_command_path(value: &str, cwd: &Path) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

pub(crate) fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn windows_resolution_applies_pathext_to_bare_commands() {
        let temp = tempfile::tempdir().expect("temp dir");
        let node = temp.path().join("node.EXE");
        fs::write(&node, b"stub").expect("write executable fixture");
        make_executable(&node);
        let search_path = env::join_paths([temp.path()]).expect("search path");

        let resolved = resolve_executable_for_platform(
            "node",
            Some(&search_path),
            temp.path(),
            true,
            Some(OsStr::new(".COM;.EXE;.CMD")),
        );

        assert_eq!(resolved, Some(node));
    }

    #[test]
    fn windows_resolution_does_not_append_pathext_to_explicit_extensions() {
        let candidates = executable_candidates(
            Path::new("node.custom"),
            true,
            Some(OsStr::new(".EXE;.CMD")),
        )
        .collect::<Vec<_>>();

        assert_eq!(candidates, vec![PathBuf::from("node.custom")]);
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("fixture permissions");
        }
        #[cfg(not(unix))]
        let _ = path;
    }
}
