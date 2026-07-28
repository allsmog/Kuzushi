//! Binary-availability probes shared by every MCP backend.
//!
//! Each MCP server's `health` tool calls these to report whether the
//! external binary it depends on is present, with the version string
//! when so. Backends never panic on missing binaries — they degrade to
//! `ready: false` and let the consumer (or facade) decide.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BinaryProbe {
    pub binary: String,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// PATH-search a binary, returning its absolute path when found.
pub fn which(binary: &str) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    let path_extensions = std::env::var_os("PATHEXT");
    which_in_path(binary, &path_env, path_extensions.as_deref(), cfg!(windows))
}

fn which_in_path(
    binary: &str,
    path_env: &OsStr,
    path_extensions: Option<&OsStr>,
    windows: bool,
) -> Option<PathBuf> {
    let names = executable_names(binary, path_extensions, windows);
    for directory in std::env::split_paths(path_env) {
        for name in &names {
            let candidate = directory.join(name);
            if is_regular_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn executable_names(binary: &str, path_extensions: Option<&OsStr>, windows: bool) -> Vec<OsString> {
    if !windows || std::path::Path::new(binary).extension().is_some() {
        return vec![OsString::from(binary)];
    }
    let mut names: Vec<OsString> = Vec::new();
    let extensions = path_extensions
        .and_then(OsStr::to_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(".COM;.EXE;.BAT;.CMD");
    for extension in extensions.split(';').filter_map(normalized_extension) {
        let mut name = OsString::from(binary);
        name.push(extension);
        if !names
            .iter()
            .any(|candidate| os_eq_ignore_case(candidate, &name))
        {
            names.push(name);
        }
    }
    names
}

fn normalized_extension(extension: &str) -> Option<String> {
    let extension = extension.trim();
    let suffix = extension.strip_prefix('.').unwrap_or(extension);
    if !["COM", "EXE", "BAT", "CMD"]
        .iter()
        .any(|supported| suffix.eq_ignore_ascii_case(supported))
    {
        return None;
    }
    Some(if extension.starts_with('.') {
        extension.to_string()
    } else {
        format!(".{extension}")
    })
}

fn os_eq_ignore_case(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn is_regular_executable(path: &std::path::Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Probe a binary by running `bin <args>` and capturing the first line of
/// stdout (or stderr, if stdout is empty — many tools print version info to
/// stderr). Returns `None` when the binary isn't on PATH or fails to spawn.
pub async fn probe(binary: &str, version_args: &[&str]) -> BinaryProbe {
    let path = which(binary);
    let found = path.is_some();
    let mut version = None;

    if let Some(path) = path.as_ref() {
        let mut command = Command::new(path);
        command
            .args(version_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Ok(output) =
            crate::process::run_guarded_output(&mut command, "MCP dependency probe").await
        {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let first = stdout
                .lines()
                .next()
                .filter(|s| !s.is_empty())
                .or_else(|| stderr.lines().next().filter(|s| !s.is_empty()))
                .map(str::to_string);
            version = first;
        }
    }

    BinaryProbe {
        binary: binary.to_string(),
        found,
        path,
        version,
    }
}

/// Convenience: probe a list of binaries and produce a `Result`-shaped
/// view (`Ok(versions)` if all found, `Err(missing)` otherwise) for use in
/// `health` tool implementations.
pub async fn probe_all(probes: &[(&str, &[&str])]) -> HealthSummary {
    let mut probes_out = Vec::with_capacity(probes.len());
    let mut missing = Vec::new();
    for (bin, args) in probes {
        let p = probe(bin, args).await;
        if !p.found {
            missing.push(bin.to_string());
        }
        probes_out.push(p);
    }
    HealthSummary {
        ready: missing.is_empty(),
        probes: probes_out,
        missing,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthSummary {
    pub ready: bool,
    pub probes: Vec<BinaryProbe>,
    pub missing: Vec<String>,
}

/// Re-export the `Result` alias for convenience inside backend crates.
#[doc(hidden)]
pub type DoctorResult<T> = Result<T>;

#[cfg(test)]
mod tests {
    use super::*;

    /// `which` should resolve `/bin/sh` (universally present on test hosts).
    #[test]
    fn which_finds_universal_binary() {
        let candidates = ["sh", "true", "ls"];
        let any_found = candidates.iter().any(|c| which(c).is_some());
        assert!(any_found, "at least one of sh/true/ls should be on PATH");
    }

    /// Random nonsense binary returns None.
    #[test]
    fn which_returns_none_for_missing() {
        assert!(which("kuzushi-no-such-binary-zzz-99").is_none());
    }

    #[test]
    fn windows_candidates_include_pathext_and_default_exe_names() {
        let configured = executable_names("codeql", Some(OsStr::new("COM;.Exe;.CMD")), true);
        assert_eq!(configured, ["codeql.COM", "codeql.Exe", "codeql.CMD"]);
        assert_eq!(
            executable_names("codeql", None, true),
            ["codeql.COM", "codeql.EXE", "codeql.BAT", "codeql.CMD"]
        );
        assert_eq!(
            executable_names("codeql.exe", Some(OsStr::new(".EXE")), true),
            ["codeql.exe"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_lookup_finds_codeql_exe_via_mixed_case_pathext() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("codeql"), "extensionless decoy").unwrap();
        let executable = temp.path().join("codeql.exe");
        std::fs::write(&executable, "test executable").unwrap();
        let path = std::env::join_paths([temp.path()]).unwrap();

        let resolved = which_in_path("codeql", &path, Some(OsStr::new(".Com;.EXE")), true);

        assert!(resolved
            .as_ref()
            .and_then(|candidate| candidate.file_name())
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("codeql.exe")));
    }

    #[tokio::test]
    async fn probe_missing_returns_not_found() {
        let p = probe("kuzushi-no-such-binary-zzz-99", &["--version"]).await;
        assert!(!p.found);
        assert!(p.path.is_none());
        assert!(p.version.is_none());
    }

    #[tokio::test]
    async fn probe_all_aggregates_missing() {
        let summary = probe_all(&[
            ("kuzushi-missing-a", &["--version"]),
            ("kuzushi-missing-b", &["--version"]),
        ])
        .await;
        assert!(!summary.ready);
        assert_eq!(summary.missing.len(), 2);
    }
}
