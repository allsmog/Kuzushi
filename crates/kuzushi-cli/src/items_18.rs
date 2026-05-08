use super::prelude::*;
use super::*;

pub(crate) fn check_bridge_command(config: &kuzushi_core::V2Config) -> DoctorCheck {
    match PiAgentCoreRuntime::from_config(config, current_dir_for_doctor()) {
        Ok(runtime) => {
            let command = runtime.command();
            if command.is_empty() {
                return DoctorCheck::fail(
                    "pi-agent-core bridge",
                    "bridge command is empty",
                    "Set runtime.agent_bridge_command to an executable command.",
                );
            }
            let cwd = current_dir_for_doctor();
            let executable = resolve_executable(&command[0], env::var_os("PATH").as_deref(), &cwd);
            let Some(executable) = executable else {
                return DoctorCheck::fail(
                    "pi-agent-core bridge",
                    format!("bridge executable {:?} was not found", command[0]),
                    "Install Node.js or set runtime.agent_bridge_command to an executable bridge.",
                );
            };

            if let Some(script) = command
                .get(1)
                .filter(|arg| arg.ends_with("pi-agent-core-bridge.mjs"))
            {
                let script_path = resolve_command_path(script, &cwd);
                if !script_path.exists() {
                    return DoctorCheck::fail(
                        "pi-agent-core bridge",
                        format!("bridge script {} was not found", script_path.display()),
                        "Run from a source checkout, build the npm package, or set runtime.agent_bridge_command.",
                    );
                }
            }

            DoctorCheck::ok(
                "pi-agent-core bridge",
                format!("{} via {}", command.join(" "), executable.display()),
            )
        }
        Err(error) => DoctorCheck::fail(
            "pi-agent-core bridge",
            error.to_string(),
            "Set runtime.agent_bridge_command to an executable command.",
        ),
    }
}

pub(crate) fn current_dir_for_doctor() -> PathBuf {
    env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn resolve_executable(
    binary: &str,
    path: Option<&std::ffi::OsStr>,
    cwd: &Path,
) -> Option<PathBuf> {
    let candidate = Path::new(binary);
    if candidate.components().count() > 1 {
        let resolved = resolve_command_path(binary, cwd);
        return is_executable_file(&resolved).then_some(resolved);
    }

    path.into_iter()
        .flat_map(env::split_paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable_file(candidate))
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

pub(crate) fn print_doctor_plain(report: &DoctorReport) {
    println!("Kuzushi doctor");
    println!("Target: {}", report.target.display());
    for check in &report.checks {
        println!(
            "[{}] {:<20} {}",
            check.status.label(),
            check.name,
            check.detail
        );
        if let Some(next) = &check.next {
            println!("      Next: {next}");
        }
    }
    println!(
        "Summary: {} ok, {} warn, {} fail",
        report.count(DoctorStatus::Ok),
        report.count(DoctorStatus::Warn),
        report.count(DoctorStatus::Fail)
    );
}
