use crate::backend::SandboxBackend;

use super::SandboxExecOptions;

pub fn build_argv(backend: SandboxBackend, opts: &SandboxExecOptions) -> Vec<String> {
    match backend {
        SandboxBackend::Plain => opts.cmd.clone(),
        SandboxBackend::Bwrap => build_bwrap_argv(opts),
        SandboxBackend::Podman => build_podman_argv(opts),
    }
}

pub(crate) fn build_bwrap_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut argv = vec!["bwrap".to_string()];
    append_bwrap_process_isolation(&mut argv, opts.network);
    append_bwrap_filesystem(&mut argv);
    append_bwrap_mounts(&mut argv, opts);
    append_bwrap_process_options(&mut argv, opts);
    argv.push("--".to_string());
    argv.extend(opts.cmd.iter().cloned());
    argv
}

fn append_bwrap_process_isolation(argv: &mut Vec<String>, network: bool) {
    argv.extend(["--die-with-parent".to_string()]);
    argv.extend(["--unshare-all".to_string()]);
    if network {
        argv.extend(["--share-net".to_string()]);
    }
    argv.extend(["--cap-drop".to_string(), "ALL".to_string()]);
    argv.extend(["--new-session".to_string()]);
}

fn append_bwrap_filesystem(argv: &mut Vec<String>) {
    for path in ["/usr", "/lib", "/lib64", "/bin", "/etc/alternatives"] {
        if std::path::Path::new(path).exists() {
            argv.extend(["--ro-bind".to_string(), path.to_string(), path.to_string()]);
        }
    }
    argv.extend([
        "--symlink".to_string(),
        "usr/bin".to_string(),
        "/sbin".to_string(),
    ]);
    argv.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    argv.extend(["--tmpfs".to_string(), "/work".to_string()]);
}

fn append_bwrap_mounts(argv: &mut Vec<String>, opts: &SandboxExecOptions) {
    for mount in &opts.read_only_mounts {
        argv.extend([
            "--ro-bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }
    for mount in &opts.read_write_mounts {
        argv.extend([
            "--bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }
}

pub(crate) fn build_podman_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut argv = vec!["podman".to_string(), "run".to_string()];
    append_podman_isolation(&mut argv, opts);
    append_podman_mounts(&mut argv, opts);
    append_podman_process_options(&mut argv, opts);
    argv.push("--entrypoint=".to_string());
    argv.extend(opts.cmd.iter().cloned());
    argv
}

fn append_podman_isolation(argv: &mut Vec<String>, opts: &SandboxExecOptions) {
    argv.extend(["--rm".to_string()]);
    argv.extend(["--read-only".to_string()]);
    argv.extend(["--cap-drop=ALL".to_string()]);
    argv.extend([
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
    ]);
    if !opts.network {
        argv.extend(["--network=none".to_string()]);
    }
    if let Some(mb) = opts.memory_mb {
        argv.extend(["--memory".to_string(), format!("{mb}m")]);
    }
    argv.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    argv.extend(["--tmpfs".to_string(), "/work".to_string()]);
}

fn append_podman_mounts(argv: &mut Vec<String>, opts: &SandboxExecOptions) {
    for mount in &opts.read_only_mounts {
        argv.extend([
            "-v".to_string(),
            format!(
                "{}:{}:ro",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }
    for mount in &opts.read_write_mounts {
        argv.extend([
            "-v".to_string(),
            format!(
                "{}:{}",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }
}

fn append_bwrap_process_options(argv: &mut Vec<String>, opts: &SandboxExecOptions) {
    if let Some(wd) = &opts.workdir {
        argv.extend(["--chdir".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        argv.extend(["--setenv".to_string(), k.clone(), v.clone()]);
    }
}

fn append_podman_process_options(argv: &mut Vec<String>, opts: &SandboxExecOptions) {
    if let Some(wd) = &opts.workdir {
        argv.extend(["-w".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        argv.extend(["-e".to_string(), format!("{k}={v}")]);
    }
}
