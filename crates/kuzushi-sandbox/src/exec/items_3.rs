use super::prelude::*;
use super::*;

pub(crate) fn build_bwrap_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut a: Vec<String> = vec!["bwrap".to_string()];
    a.extend(["--die-with-parent".to_string()]);
    a.extend(["--unshare-all".to_string()]);
    if opts.network {
        a.extend(["--share-net".to_string()]);
    }
    a.extend(["--cap-drop".to_string(), "ALL".to_string()]);
    a.extend(["--new-session".to_string()]);

    // Standard read-only system mounts.
    for path in ["/usr", "/lib", "/lib64", "/bin", "/etc/alternatives"] {
        if std::path::Path::new(path).exists() {
            a.extend(["--ro-bind".to_string(), path.to_string(), path.to_string()]);
        }
    }
    // Symlink /sbin and /usr/sbin to /usr/bin so basic tools resolve.
    a.extend([
        "--symlink".to_string(),
        "usr/bin".to_string(),
        "/sbin".to_string(),
    ]);

    // Tmpfs for /tmp and /work.
    a.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    a.extend(["--tmpfs".to_string(), "/work".to_string()]);

    // Operator-supplied mounts.
    for mount in &opts.read_only_mounts {
        a.extend([
            "--ro-bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }
    for mount in &opts.read_write_mounts {
        a.extend([
            "--bind".to_string(),
            mount.host_path.display().to_string(),
            mount.guest_path.display().to_string(),
        ]);
    }

    if let Some(wd) = &opts.workdir {
        a.extend(["--chdir".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        a.extend(["--setenv".to_string(), k.clone(), v.clone()]);
    }
    a.push("--".to_string());
    a.extend(opts.cmd.iter().cloned());
    a
}

pub(crate) fn build_podman_argv(opts: &SandboxExecOptions) -> Vec<String> {
    let mut a: Vec<String> = vec!["podman".to_string(), "run".to_string()];
    a.extend(["--rm".to_string()]);
    a.extend(["--read-only".to_string()]);
    a.extend(["--cap-drop=ALL".to_string()]);
    a.extend([
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
    ]);
    if !opts.network {
        a.extend(["--network=none".to_string()]);
    }
    if let Some(mb) = opts.memory_mb {
        a.extend(["--memory".to_string(), format!("{mb}m")]);
    }
    a.extend(["--tmpfs".to_string(), "/tmp".to_string()]);
    a.extend(["--tmpfs".to_string(), "/work".to_string()]);

    for mount in &opts.read_only_mounts {
        a.extend([
            "-v".to_string(),
            format!(
                "{}:{}:ro",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }
    for mount in &opts.read_write_mounts {
        a.extend([
            "-v".to_string(),
            format!(
                "{}:{}",
                mount.host_path.display(),
                mount.guest_path.display()
            ),
        ]);
    }

    if let Some(wd) = &opts.workdir {
        a.extend(["-w".to_string(), wd.display().to_string()]);
    }
    for (k, v) in &opts.env {
        a.extend(["-e".to_string(), format!("{k}={v}")]);
    }

    // Default rootless image; operator can override via env mount or
    // by passing `--image` in their cmd. For the verify pipeline we
    // expect the cmd to start with the image name and command.
    a.push("--entrypoint=".to_string());
    a.extend(opts.cmd.iter().cloned());
    a
}
