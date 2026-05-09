use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;

/// Locate a joern binary by name (`joern`, `joern-parse`, `java`, …).
/// Checks, in order:
/// 1. `$PATH`
/// 2. The `KUZUSHI_JOERN_BIN` env var (joern only — operators set it
///    when joern is installed in a non-standard location and the
///    auto-spawn path needs an explicit override).
/// 3. Hardcoded fallbacks for the common Linux install layouts:
///    `/opt/joern/joern-cli/{name}`, `/opt/joern/joern-cli/bin/{name}`,
///    `/usr/local/bin/{name}`, `/usr/bin/{name}`.
///
/// Centralised here so `ensure_joern_available`, the `joern.health`
/// extended probe, and the auto-spawn launcher path all agree on
/// which joern they're talking about. Without this, the bridge could
/// see `joern.health` succeed (find joern via the hardcoded path) but
/// every other joern tool fail with `BackendUnavailable: joern not on
/// PATH` because the bare PATH lookup missed it.
pub(crate) fn locate_joern_binary(name: &str) -> Option<PathBuf> {
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if name == "joern" {
        if let Some(env_path) = std::env::var_os("KUZUSHI_JOERN_BIN") {
            let candidate = PathBuf::from(env_path);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for hardcoded in [
        format!("/opt/joern/joern-cli/{name}"),
        format!("/opt/joern/joern-cli/bin/{name}"),
        format!("/usr/local/bin/{name}"),
        format!("/usr/bin/{name}"),
    ] {
        let p = PathBuf::from(hardcoded);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

pub(crate) fn ensure_joern_available() -> Result<()> {
    if locate_joern_binary("joern-parse").is_none() && locate_joern_binary("joern").is_none() {
        anyhow::bail!(
            "BackendUnavailable: joern not on PATH or any known install location \
             (/opt/joern/joern-cli/{{joern,joern-parse}}, /usr/local/bin/, /usr/bin/). \
             Install via https://docs.joern.io/installation \
             or set KUZUSHI_JOERN_BIN=<path-to-joern>."
        );
    }
    Ok(())
}

pub(crate) fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

pub(crate) fn parse_raw_json_or_string(raw: String) -> Value {
    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialise tests that mutate $PATH or KUZUSHI_JOERN_BIN so
    /// concurrent tests don't race. Each test acquires the lock for
    /// the duration of its env mutation.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn locate_joern_finds_via_path_first() {
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("joern");
        std::fs::write(&bin, "#!/bin/sh\necho 0").unwrap();
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", tmp.path());
        let found = locate_joern_binary("joern");
        match original_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        assert_eq!(found.as_deref(), Some(bin.as_path()));
    }

    #[test]
    fn locate_joern_falls_back_to_kuzushi_joern_bin_for_joern() {
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("joern-launcher");
        std::fs::write(&bin, "#!/bin/sh\necho 0").unwrap();
        let original_path = std::env::var_os("PATH");
        let original_bin = std::env::var_os("KUZUSHI_JOERN_BIN");
        // Empty PATH so the env-var fallback is the only winning route.
        std::env::set_var("PATH", "");
        std::env::set_var("KUZUSHI_JOERN_BIN", &bin);
        let found = locate_joern_binary("joern");
        match original_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match original_bin {
            Some(v) => std::env::set_var("KUZUSHI_JOERN_BIN", v),
            None => std::env::remove_var("KUZUSHI_JOERN_BIN"),
        }
        assert_eq!(found.as_deref(), Some(bin.as_path()));
    }

    #[test]
    fn locate_joern_ignores_kuzushi_joern_bin_for_other_binaries() {
        // KUZUSHI_JOERN_BIN points at the joern launcher specifically;
        // it must not redirect a `joern-parse` or `java` lookup to the
        // launcher path.
        let _guard = env_lock().lock().unwrap();
        let original_path = std::env::var_os("PATH");
        let original_bin = std::env::var_os("KUZUSHI_JOERN_BIN");
        std::env::set_var("PATH", "/nonexistent/path");
        std::env::set_var("KUZUSHI_JOERN_BIN", "/some/joern/path");
        let found = locate_joern_binary("joern-parse");
        match original_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        match original_bin {
            Some(v) => std::env::set_var("KUZUSHI_JOERN_BIN", v),
            None => std::env::remove_var("KUZUSHI_JOERN_BIN"),
        }
        // Either None (no hardcoded fallback exists in test sandbox)
        // or a path inside /opt/joern/joern-cli/bin, NOT the
        // KUZUSHI_JOERN_BIN value.
        if let Some(p) = found {
            assert_ne!(p, std::path::PathBuf::from("/some/joern/path"));
        }
    }

    #[test]
    fn ensure_joern_available_passes_when_locate_succeeds() {
        // Smoke test: if ANY of the lookup branches finds joern (PATH,
        // env var, hardcoded fallback), ensure_joern_available
        // returns Ok. Without a real joern install we set up a temp
        // file as the joern binary and bind PATH to that dir.
        let _guard = env_lock().lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("joern");
        std::fs::write(&bin, "#!/bin/sh\nexit 0").unwrap();
        let original_path = std::env::var_os("PATH");
        std::env::set_var("PATH", tmp.path());
        let result = ensure_joern_available();
        match original_path {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }
        assert!(result.is_ok());
    }
}
