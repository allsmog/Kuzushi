use super::*;

pub(in crate::scan) fn resolve_codeql_binary(configured: Option<&str>) -> Result<String> {
    configured_codeql_binary(configured)
        .or_else(path_codeql_binary)
        .or_else(cached_codeql_binary)
        .or_else(standard_codeql_binary)
        .with_context(|| {
            "CodeQL CLI not found. Install it with `gh extension install github/gh-codeql && gh codeql install-stub`, download it from https://github.com/github/codeql-cli-binaries/releases, or pass {\"binary\":\"/path/to/codeql\"} to codeql:scan."
        })
}

pub(in crate::scan) fn configured_codeql_binary(configured: Option<&str>) -> Option<String> {
    configured.and_then(non_empty_string).map(str::to_string)
}

pub(in crate::scan) fn path_codeql_binary() -> Option<String> {
    find_executable_on_path("codeql").map(|path| path.display().to_string())
}

pub(in crate::scan) fn cached_codeql_binary() -> Option<String> {
    dirs::home_dir()
        .map(|home| home.join(".kuzushi").join("bin").join(codeql_binary_name()))
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
}

pub(in crate::scan) fn codeql_binary_name() -> &'static str {
    if cfg!(windows) {
        "codeql.exe"
    } else {
        "codeql"
    }
}

pub(in crate::scan) fn standard_codeql_binary() -> Option<String> {
    ["/opt/homebrew/bin/codeql", "/usr/local/bin/codeql"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(|path| path.display().to_string())
}

pub(in crate::scan) fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{name}.exe"));
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}
